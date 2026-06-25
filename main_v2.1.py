#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚠️  此文件已弃用，仅保留向后兼容。
请使用  python main.py  代替。

所有特性（v2.1 连接池管理、智能重试、动态队列、性能监控）已合并到统一的 main.py。
"""

import sys
import warnings

warnings.warn(
    "main_v2.1.py 已弃用，请使用 python main.py",
    DeprecationWarning,
    stacklevel=2,
)

from main import main

if __name__ == "__main__":
    sys.argv = [arg for arg in sys.argv if arg != __file__]
    main()
