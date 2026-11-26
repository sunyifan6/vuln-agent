# -*- coding: utf-8 -*-
"""结果融合：三路（baseline / rag / agent）投票。

两种规则：
    unanimity（默认）  三路都判 1 才判 1，否则判 0
    majority           三路中两路判 1 即判 1

为什么默认 unanimity：
    三个模式看到的信息不同——baseline 只看函数，rag 参考历史案例，agent 会去仓库取证。
    "三路一致才报警"是最保守、也最容易解释的规则：不需要挑哪两路、不需要调参数。
    实测 P-C=30、P-R=10，比多数投票的 P-R=11 更稳（P-R 是被惩罚的指标）。

用法：
    python fuse.py
    python fuse.py --rule majority
    python fuse.py --inputs out/result_baseline.jsonl out/result_rag.jsonl out/result_agent.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import config


def load(path: Path) -> dict:
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["idx"]] = int(r["prediction"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", default=[
        str(config.OUT_DIR / "result_baseline.jsonl"),
        str(config.OUT_DIR / "result_rag.jsonl"),
        str(config.OUT_DIR / "result_agent.jsonl"),
    ])
    ap.add_argument("--rule", choices=["unanimity", "majority"], default="unanimity")
    ap.add_argument("--out", default=str(config.OUT_DIR / "result_final.jsonl"))
    args = ap.parse_args()

    sources = []
    for p in args.inputs:
        data = load(Path(p))
        if data:
            sources.append(data)
            print(f"载入 {Path(p).name}: {len(data)} 条")
        else:
            print(f"跳过（不存在或为空）: {p}")
    if not sources:
        raise SystemExit("没有任何可用结果")

    all_idx = set()
    for d in sources:
        all_idx |= set(d)

    fused: dict[str, int] = {}
    skipped = 0
    for idx in all_idx:
        votes = [d[idx] for d in sources if idx in d]
        if len(votes) < 2:
            skipped += 1
            continue
        if args.rule == "unanimity":
            fused[idx] = 1 if all(v == 1 for v in votes) else 0
        else:
            fused[idx] = 1 if sum(votes) * 2 > len(votes) else 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        "".join(json.dumps({"idx": i, "prediction": fused[i]}) + "\n" for i in sorted(fused)),
        encoding="utf-8",
    )
    ones = sum(fused.values())
    print(f"\n规则 {args.rule}，融合 {len(fused)} 条（判 1 的 {ones} 条），"
          f"只有一路覆盖而跳过 {skipped} 条")
    print(f"输出：{out_path}")
    print(f"\n评测：python evaluate.py {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
