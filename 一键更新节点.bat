@echo off
title Free Node Updater
echo ================================================
echo   Fetching latest free nodes + speed test
echo   About 2-4 minutes, please keep this window open
echo ================================================
echo.

C:\NodeToolPy\Scripts\python.exe "%~dp0fetch_nodes.py" --test --top 100

if errorlevel 1 (
    echo.
    echo [ERROR] Failed. Please screenshot this window to WorkBuddy.
    pause
    exit /b 1
)

type "%~dp0output\list.txt" | clip
echo.
echo ================================================
echo   DONE! Fastest 100 nodes are in your clipboard.
echo   Next steps:
echo     1. Open v2rayN
echo     2. Click an empty area of the node list
echo     3. Press Ctrl+V to import
echo ================================================
pause
