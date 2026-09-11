# 免费节点聚合器

自动抓取、合并、去重、测活互联网上的公开免费节点，输出给 v2rayN 使用的订阅文件。

## 项目结构

```
free-node-aggregator/
├── fetch_nodes.py          # 主程序：抓取 → 提取 → 去重 → (测活) → 输出
├── sources.txt             # 订阅源列表，每行一个 URL，可自行增删
├── .github/workflows/update.yml   # GitHub Actions：每小时云端自动更新并发布
└── output/
    ├── list.txt            # 纯分享链接版（带更新时间注释）
    └── list_base64.txt     # Base64 版 <-- v2rayN 订阅用这个
```

## 本地使用（最快上手）

```bash
python fetch_nodes.py          # 抓取合并
python fetch_nodes.py --test   # 抓取后做 TCP 连通性测试，过滤已失效节点
```

然后在 v2rayN 里：订阅分组 → 添加 → 地址填本地文件的绝对路径，例如：

```
C:\...\free-node-aggregator\output\list_base64.txt
```

订阅自动更新设为 30~60 分钟一次。

## 云端自动化（推荐，解决"节点秒失效"）

节点的存活窗口很短，靠手动跑没用，必须全自动循环：

1. 在 GitHub 新建仓库，把本项目全部文件推上去
2. 仓库开启 Actions（workflow 已内置：每小时抓取一次、跑连通性测试、把结果提交回仓库）
3. 你的 v2rayN 订阅地址填：
   ```
   https://raw.githubusercontent.com/<你的用户名>/<仓库名>/master/output/list_base64.txt
   ```
   直连不通就在前面加镜像前缀：`https://ghproxy.net/`

这样整个链路是全自动的：**每小时云端抓新节点 → 测活过滤死节点 → 提交到仓库 → v2rayN 每半小时自动拉最新订阅**，你什么都不用做。

## 本地定时（不想用 GitHub 的替代方案）

用 Windows 任务计划程序每小时执行一次：

```
程序: python.exe
参数: C:\...\free-node-aggregator\fetch_nodes.py --test
起始于: C:\...\free-node-aggregator
```

## 扩充节点源

编辑 `sources.txt`，每行加一个公开订阅 URL 即可。脚本兼容三种格式：
- Base64 整体编码的订阅
- 纯分享链接文本（vmess:// ss:// trojan:// hysteria2:// 等）
- 混合了 HTML/说明文字的页面（用正则兜底提取）

想覆盖"市面上"更多源，可以关注 Telegram 免费节点频道、GitHub 上搜 `free nodes` / `v2ray subscription` 的新仓库，把它们的 raw 地址加进 sources.txt。

## 提醒

- 免费节点是陌生人服务器，不要走登录凭据、网银等敏感流量
- --test 只是 TCP 连通性测试，不代表节点真可用、不被限速，最终以客户端真连接延迟为准
- 抓取遵守各来源站点的规则，仅供学习交流
