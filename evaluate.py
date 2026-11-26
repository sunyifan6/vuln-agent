# -*- coding: utf-8 -*-
"""调用官方评分脚本，并输出成对统计。

用法：
    python evaluate.py out/result_rag.jsonl
    python evaluate.py out/result_baseline.jsonl
"""

from __future__ import annotations

import argparse
import subprocess
import sys

import config


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("result", help="结果 jsonl 路径")
    args = ap.parse_args()

    if not config.EVAL_SCRIPT.exists():
        raise SystemExit(f"找不到官方评分脚本：{config.EVAL_SCRIPT}")

    cmd = [sys.executable, str(config.EVAL_SCRIPT),
           "--dataset", str(config.TEST_PATH),
           "--result", args.result]
    print("运行：" + " ".join(cmd) + "\n")
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
