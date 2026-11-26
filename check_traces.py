# -*- coding: utf-8 -*-
"""跑完之后用这个检查轨迹：工具用了几次、sha 有没有解析对。

用法：
    python check_traces.py                 # 默认看 out/traces_full.jsonl
    python check_traces.py --mode agent
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter

import config


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="full")
    args = ap.parse_args()

    path = config.OUT_DIR / f"traces_{args.mode}.jsonl"
    if not path.exists():
        raise SystemExit(f"文件不存在：{path}")

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    used = [r for r in rows if r.get("trace")]
    calls = sum(len(r.get("trace") or []) for r in rows)

    print(f"文件：{path.name}")
    print(f"样本数：{len(rows)}")
    print(f"用过工具的样本：{len(used)}（{len(used) / max(len(rows), 1):.1%}）")
    print(f"工具调用总次数：{calls}")
    print(f"步数分布：{dict(Counter(r.get('steps') for r in rows))}")
    print(f"工具分布：{dict(Counter(t['tool'] for r in rows for t in (r.get('trace') or [])))}")
    print()

    print("sha 解析核对（只看用过工具的样本）：")
    wrong = 0
    for r in used[:10]:
        m = re.search(r"/commit/([0-9a-f]+)", r.get("commit_url") or "")
        commit_sha = m.group(1) if m else "?"
        sha = r.get("sha") or "None"
        if sha == "None":
            tag = "未解析"
            wrong += 1
        elif sha[:12] == commit_sha[:12]:
            tag = "本提交（label 应为 0）" if r.get("label") == 0 else "★ 本提交但 label=1"
            wrong += r.get("label") == 1
        else:
            tag = "父提交（label 应为 1）" if r.get("label") == 1 else "★ 父提交但 label=0"
            wrong += r.get("label") == 0
        print(f"  idx={r['idx']} label={r['label']}  commit={commit_sha[:10]}  "
              f"sha={sha[:10]}  {tag}")

    print()
    print("[OK] sha 解析全部匹配" if wrong == 0 else f"[FAIL] 有 {wrong} 条 sha 与 label 不匹配")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
