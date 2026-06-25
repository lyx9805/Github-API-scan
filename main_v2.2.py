#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚠️  此文件已弃用，仅保留向后兼容。
请使用  python main.py  代替。

所有 v2.2 特性（智能缓存、批量验证、域名健康追踪）已合并到统一的 main.py。
"""

import sys
import warnings

warnings.warn(
    "main_v2.2.py 已弃用，请使用 python main.py",
    DeprecationWarning,
    stacklevel=2,
)

# 委派到统一入口
from main import main

if __name__ == "__main__":
    sys.argv = [arg for arg in sys.argv if arg != __file__]
    main()
