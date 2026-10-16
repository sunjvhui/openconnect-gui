#!/bin/sh
# OpenConnect GUI 启动器 — 自动挑选带可用 tkinter 的 Python
DIR="$(cd "$(dirname "$0")" && pwd)"
export TK_SILENCE_DEPRECATION=1

# 优先: Homebrew Python (需 python-tk@3.13: brew install python-tk@3.13)
if [ -x /opt/homebrew/bin/python3.13 ] && /opt/homebrew/bin/python3.13 -c "import tkinter" 2>/dev/null; then
    exec /opt/homebrew/bin/python3.13 "$DIR/openconnect_gui.py" "$@"
fi
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c "import tkinter" 2>/dev/null; then
        exec "$py" "$DIR/openconnect_gui.py" "$@"
    fi
done
echo "错误: 未找到带 tkinter 的 Python。" >&2
echo "请安装: brew install python@3.13 python-tk@3.13" >&2
exit 1
