# -*- coding: utf-8 -*-
"""一键跑完整流程：full 模式（RAG 检索 + 仓库工具）→ 评测。

full = PPT 第 4 页的 pipeline：
    检索知识库 → Agent 初步分析 → 按需读仓库 → 报告

用法：
    python run_final.py                 # 全量 300 条（约 15 分钟）
    python run_final.py --limit 40      # 先跑 40 条试水
    python run_final.py --rebuild-index # 重建知识库索引

成本参考（deepseek-flash，非思考模式）：全量约 115 万 token，15 元以内。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import config


def run(cmd: list[str]) -> int:
    print("\n$ " + " ".join(cmd), flush=True)
    return subprocess.call(cmd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rebuild-index", action="store_true")
    args = ap.parse_args()

    py = sys.executable
    cmd = [py, "run_all.py", "--mode", "full", "--no-resume"]
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    if args.rebuild_index:
        cmd += ["--rebuild-index"]

    if run(cmd) != 0:
        return 1

    src = config.OUT_DIR / "result_full.jsonl"
    dst = config.OUT_DIR / "result_final.jsonl"
    shutil.copyfile(src, dst)
    print(f"\n已生成提交文件：{dst}")

    run([py, "evaluate.py", str(dst)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
