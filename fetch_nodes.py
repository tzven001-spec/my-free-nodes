# -*- coding: utf-8 -*-
"""
免费节点聚合器
从 sources.txt 里的公开订阅源抓取节点分享链接，
去重、(可选)TCP 连通性测试后，输出给 v2rayN 用的 Base64 订阅文件。

用法:
  python fetch_nodes.py            # 只抓取合并
  python fetch_nodes.py --test     # 抓取后再做 TCP 连通性测试(慢)
"""

import base64
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import socket
import sys
import urllib.request

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

ROOT = pathlib.Path(__file__).parent
SOURCES_FILE = ROOT / "sources.txt"
OUT_DIR = ROOT / "output"

# 支持的节点分享链接协议(与 v2rayN 兼容)
SCHEMES = (
    "vmess://", "vless://", "ss://", "ssr://", "trojan://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://", "socks5://",
)

# raw 直连不通时依次尝试的镜像前缀
MIRROR_PREFIXES = ["", "https://ghproxy.net/", "https://ghproxy.cfd/"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) free-node-aggregator",
    "Accept": "*/*",
}


def http_get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_source(url: str) -> str:
    """抓取一个源，自动尝试镜像前缀。"""
    for prefix in MIRROR_PREFIXES:
        try:
            data = http_get(prefix + url)
            text = data.decode("utf-8", errors="replace")
            if text.strip():
                print(f"  [OK] {url}  (via {'direct' if not prefix else 'mirror'})")
                return text
        except Exception:
            continue
    print(f"  [FAIL] {url}")
    return ""


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def clash_to_link(p: dict) -> str | None:
    """把 Clash 配置里的单个 proxies 条目反向转换为分享链接。"""
    try:
        t = p.get("type", "")
        name = p.get("name", "node")
        server, port = str(p.get("server")), int(p.get("port", 0))
        if not server or not port:
            return None
        qs = []
        if p.get("sni"):
            qs.append(f"sni={p['sni']}")
        if p.get("skip-cert-verify"):
            qs.append("allowInsecure=1")

        if t == "ss":
            userinfo = f"{p.get('cipher', 'aes-256-gcm')}:{p.get('password', '')}"
            return f"ss://{_b64(userinfo + f'@{server}:{port}')}#{name}"

        if t == "vmess":
            obj = {
                "v": "2", "ps": name, "add": server, "port": str(port),
                "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                "path": p.get("ws-opts", {}).get("path", ""),
                "tls": "tls" if p.get("tls") else "", "sni": p.get("sni", ""),
            }
            return f"vmess://{_b64(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))}"

        if t == "vless":
            net = p.get("network", "tcp")
            security = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
            if security == "reality":
                ro = p["reality-opts"]
                qs = [f"security=reality", f"pbk={ro.get('public-key', '')}"]
                if ro.get("short-id"):
                    qs.append(f"sid={ro['short-id']}")
            elif security == "tls":
                qs = [f"security=tls"]
            qs.append(f"type={net}")
            if p.get("client-fingerprint"):
                qs.append(f"fp={p['client-fingerprint']}")
            if p.get("flow"):
                qs.append(f"flow={p['flow']}")
            if net in ("ws", "grpc"):
                wopts = p.get("ws-opts", {}) or p.get("grpc-opts", {})
                if net == "ws":
                    qs.append(f"path={wopts.get('path', '/')}")
                    h = wopts.get("headers", {}).get("Host")
                    if h:
                        qs.append(f"host={h}")
                else:
                    sn = (wopts.get("grpc-service-name") or "")
                    qs.append(f"serviceName={sn}")
            if p.get("sni"):
                qs.append(f"sni={p['sni']}")
            return f"vless://{p.get('uuid', '')}@{server}:{port}?{'&'.join(qs)}#{name}"

        if t == "trojan":
            qs = ["security=tls"] + qs
            qs.append("type=tcp")
            return f"trojan://{p.get('password', '')}@{server}:{port}?{'&'.join(qs)}#{name}"

        if t in ("hysteria2", "hy2"):
            obfs = p.get("obfs")
            if obfs:
                qs.append(f"obfs={obfs}")
                if p.get("obfs-password"):
                    qs.append(f"obfs-password={p['obfs-password']}")
            return f"hysteria2://{p.get('password', '')}@{server}:{port}?{'&'.join(qs)}#{name}"

        return None  # socks5/http/anytls 等类型暂不转换
    except Exception:
        return None


def extract_from_clash_yaml(text: str) -> list[str]:
    """解析 Clash YAML 配置里的 proxies 列表并转换为分享链接。"""
    if not HAS_YAML:
        return []
    try:
        data = yaml.safe_load(text)
        proxies = (data or {}).get("proxies") or []
    except Exception:
        return []
    links = [l for l in (clash_to_link(p) for p in proxies) if l]
    if links:
        print(f"    (从 Clash YAML 解析出 {len(links)} 个节点)")
    return links


def extract_links(text: str) -> list[str]:
    """从一段文本(Base64 订阅、纯分享链接、混合文本)里提取所有节点链接。"""
    links: list[str] = []

    # 先尝试整体 Base64 解码
    stripped = re.sub(r"\s+", "", text)
    if stripped and "://" not in stripped[:200]:
        try:
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
            if SCHEMES[0][:4] in decoded or "://" in decoded:
                text = decoded
        except Exception:
            pass

    # 逐行匹配协议头
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(SCHEMES):
            links.append(line)

    # 再用正则兜底抓一遍(防止节点链接混在 HTML/长文本里)
    pattern = re.compile(r"(?:" + "|".join(re.escape(s) for s in SCHEMES) + r")\S+")
    for m in pattern.findall(text):
        links.append(m.rstrip(")>,\"'"))

    return links


def parse_host_port(link: str) -> tuple[str, int] | None:
    """粗略解析节点链接里的 host:port, 用于连通性测试。"""
    try:
        scheme, _, rest = link.partition("://")
        rest = rest.split("#", 1)[0].split("?", 1)[0]

        if scheme == "vmess":
            padded = rest + "=" * (-len(rest) % 4)
            import json
            obj = json.loads(base64.b64decode(padded, validate=False))
            return str(obj.get("add")), int(obj.get("port", 0))

        if scheme == "ss" and "@" not in rest:
            # ss://base64(method:pass@host:port) 整体编码的情况
            padded = rest + "=" * (-len(rest) % 4)
            inner = base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
            rest = inner.split("@", 1)[-1]

        m = re.search(r"@?([\w.\-\[\]]+):(\d+)", rest)
        if m:
            return m.group(1).strip("[]"), int(m.group(2))
    except Exception:
        pass
    return None


def tcp_latency(args: tuple[str, int]) -> float | None:
    """TCP 连接测试，返回连接耗时毫秒数，失败返回 None。"""
    host, port = args
    s = socket.socket()
    s.settimeout(5)
    t0 = datetime.datetime.now()
    try:
        s.connect((host, port))
        return (datetime.datetime.now() - t0).total_seconds() * 1000
    except Exception:
        return None
    finally:
        s.close()


def tag_latency(link: str, ms: float) -> str:
    """把测速结果写进节点名称，方便在 v2rayN 里直接挑。"""
    tag = f"[{ms:.0f}ms]"
    if "#" in link:
        base, name = link.split("#", 1)
        name = re.sub(r"\[\d+ms\]", "", name)
        return f"{base}#{name}{tag}"
    return f"{link}{tag}"


def dedup(links: list[str]) -> list[str]:
    seen, out = set(), []
    for l in links:
        key = hashlib_key(l)
        if key not in seen:
            seen.add(key)
            out.append(l)
    return out


def hashlib_key(link: str) -> str:
    import hashlib
    # 去掉名称部分再哈希，同一服务器换个名字也能去重
    core = link.split("#", 1)[0]
    return hashlib.md5(core.encode()).hexdigest()


def main() -> None:
    do_test = "--test" in sys.argv

    if not SOURCES_FILE.exists():
        print("找不到 sources.txt")
        sys.exit(1)

    sources = [
        s.strip() for s in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
        if s.strip() and not s.strip().startswith("#")
    ]
    print(f"共 {len(sources)} 个源，开始抓取...\n")

    all_links: list[str] = []
    for url in sources:
        text = fetch_source(url)
        if text:
            # Clash YAML 源：单独走 YAML 解析(保留原始分享链接提取作为兜底)
            if re.search(r"\.(yml|yaml)(\?.*)?$", url) or text.lstrip().startswith(("proxies:", "port:", "mixed-port:")):
                yaml_links = extract_from_clash_yaml(text)
                all_links.extend(yaml_links)
            all_links.extend(extract_links(text))

    links = dedup(all_links)
    print(f"\n原始 {len(all_links)} 条，去重后 {len(links)} 条")

    if do_test and links:
        top_n = 100
        for i, a in enumerate(sys.argv):
            if a == "--top" and i + 1 < len(sys.argv):
                try:
                    top_n = max(1, int(sys.argv[i + 1]))
                except ValueError:
                    pass

        pairs = [(l, parse_host_port(l)) for l in links]
        targets = list({t for _, t in pairs if t})
        print(f"对 {len(targets)} 个节点测速(约 1~3 分钟)...")

        latencies: dict[tuple[str, int], float] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            for t, ms in zip(targets, ex.map(tcp_latency, targets)):
                if ms is not None:
                    latencies[t] = ms

        scored = sorted(
            ((latencies[t], l) for l, t in pairs if t and t in latencies),
            key=lambda x: x[0],
        )
        kept = scored[:top_n]
        links = [tag_latency(l, ms) for ms, l in kept]
        print(f"测活通过 {len(scored)} 条，保留延迟最低的 {len(links)} 条(已把延迟写进节点名)")

    OUT_DIR.mkdir(exist_ok=True)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    plain_path = OUT_DIR / "list.txt"
    b64_path = OUT_DIR / "list_base64.txt"
    plain_path.write_text(f"# Update: {now}\n" + "\n".join(links) + "\n", encoding="utf-8")
    body = "\n".join(links).encode("utf-8")
    b64_path.write_bytes(base64.b64encode(body))

    print(f"\n已输出:\n  {plain_path}\n  {b64_path}  <-- 给 v2rayN 订阅用")
    print("在 v2rayN 里把订阅地址指向本地文件路径即可，或部署到 GitHub 用 raw 链接更新。")


if __name__ == "__main__":
    main()
