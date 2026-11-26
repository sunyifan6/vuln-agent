# -*- coding: utf-8 -*-
"""批量运行：把测试集跑完，输出官方格式的 result.jsonl。

用法：
    python run_all.py --mode baseline            # 只给函数（最便宜）
    python run_all.py --mode rag                 # 函数 + 历史案例（推荐）
    python run_all.py --mode agent --limit 20    # 函数 + 仓库工具（最贵）

    python run_all.py --mode rag --limit 10      # 先跑 10 条试水
    python run_all.py --mode rag --no-resume     # 从头跑

产出：
    out/result_<mode>.jsonl    {"idx": 整数, "prediction": 0|1}
    out/traces_<mode>.jsonl    全部细节，用于错误分析
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import config
import dataio
import judge
import rag
import repo


def load_done(path: Path) -> set:
    if not path.exists():
        return set()
    done = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                done.add(json.loads(line)["idx"])
            except (json.JSONDecodeError, KeyError):
                continue
    return done


def make_get_root(sample: dict):
    """惰性仓库：模型第一次调用工具时才解析 sha、下载、解压。"""

    def _get():
        if not sample.get("sha"):
            parsed = dataio.parse_commit_url(sample.get("commit_url", ""))
            if not parsed:
                raise RuntimeError("commit_url 无法解析")
            owner, name, sha = parsed
            if sample.get("label") == 1:
                sha = dataio.parent_sha(owner, name, sha)
            sample["repo"] = f"{owner}/{name}"
            sample["sha"] = sha
        return repo.ensure(sample)

    return _get


def main() -> int:
    ap = argparse.ArgumentParser(description="批量漏洞检测")
    ap.add_argument("--mode", choices=["baseline", "rag", "agent", "full"], default="full",
                    help="full = RAG 检索 + 仓库工具（PPT 第 4 页 pipeline，主方案）；"
                         "baseline/rag/agent 只用于消融对比")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条")
    ap.add_argument("--offset", type=int, default=0, help="跳过前 N 条")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--rebuild-index", action="store_true")
    ap.add_argument("--result", default=None)
    ap.add_argument("--traces", default=None)
    args = ap.parse_args()

    result_path = Path(args.result or config.OUT_DIR / f"result_{args.mode}.jsonl")
    trace_path = Path(args.traces or config.OUT_DIR / f"traces_{args.mode}.jsonl")
    result_path.parent.mkdir(parents=True, exist_ok=True)

    # 不预先解析父提交：只有模型真的调用工具时才需要仓库。
    # 这样既省掉 150 次 GitHub API 调用，也省掉"模型根本不查仓库"时的下载。
    print(f"[1/3] 读取测试集（mode={args.mode}）…")
    samples = dataio.load_test(resolve_sha=False)
    if args.offset:
        samples = samples[args.offset:]
    if args.limit:
        samples = samples[: args.limit]
    print(f"      共 {len(samples)} 条，{len(samples) // 2} 对")

    index = None
    if args.mode in ("rag", "full"):
        print("[2/3] 加载知识库索引…")
        index = rag.get_index(rebuild=args.rebuild_index)
        print(f"      索引 {index.N} 条文档")
    else:
        print("[2/3] 无需索引")

    done = set() if args.no_resume else load_done(result_path)
    todo = [s for s in samples if s["idx"] not in done]
    print(f"[3/3] 已完成 {len(samples) - len(todo)}，待处理 {len(todo)}")
    if not todo:
        print("没有需要处理的数据。")
        return 0

    ok = failed = skipped = 0
    tokens = 0
    t0 = time.time()

    # --no-resume 表示"从头跑"，必须先清空旧结果，否则同一 idx 会出现两条冲突预测
    mode = "w" if args.no_resume else "a"
    with result_path.open(mode, encoding="utf-8") as fr, \
            trace_path.open(mode, encoding="utf-8") as ft:
        for i, sample in enumerate(todo, 1):
            started = time.time()
            err = None

            try:
                if args.mode == "baseline":
                    out = judge.judge_baseline(sample)
                elif args.mode == "rag":
                    cases = index.search(sample["func"], k=config.TOP_K)
                    out = judge.judge_rag(sample, cases)
                elif args.mode == "full":
                    cases = index.search(sample["func"], k=config.TOP_K)
                    try:
                        out = judge.judge_agent(sample, make_get_root(sample), cases=cases)
                    finally:
                        repo.cleanup(sample)
                else:
                    try:
                        out = judge.judge_agent(sample, make_get_root(sample))
                    finally:
                        repo.cleanup(sample)
                ok += 1
            except SystemExit:
                raise
            except Exception as exc:  # noqa: BLE001
                out = {"prediction": 0, "reason": "", "confidence": 0.0,
                       "usage": 0, "steps": 0, "trace": [], "cases": []}
                err = f"{type(exc).__name__}: {exc}"
                failed += 1

            tokens += out.get("usage", 0)
            fr.write(json.dumps({"idx": sample["idx"], "prediction": out["prediction"]},
                                ensure_ascii=False) + "\n")
            fr.flush()
            ft.write(json.dumps({
                "idx": sample["idx"], "label": sample["label"],
                "commit_url": sample.get("commit_url"),
                "repo": sample.get("repo"), "sha": sample.get("sha"),
                "prediction": out["prediction"], "reason": out.get("reason", ""),
                "confidence": out.get("confidence", 0), "evidence": out.get("evidence", []),
                "cases": out.get("cases", []), "steps": out.get("steps", 0),
                "usage": out.get("usage", 0), "trace": out.get("trace", []),
                "error": err, "elapsed": round(time.time() - started, 1),
            }, ensure_ascii=False) + "\n")
            ft.flush()

            flag = "ERR" if err else out["prediction"]
            print(f"[{i}/{len(todo)}] {sample['idx']} -> {flag}  "
                  f"label={sample['label']}  tok={out.get('usage', 0)}  "
                  f"{out.get('reason', '')[:55]}", flush=True)

    elapsed = (time.time() - t0) / 60
    print(f"\n完成：成功 {ok}，失败 {failed}，跳过 {skipped}")
    print(f"耗时 {elapsed:.1f} 分钟，共 {tokens} tokens")
    print(f"结果：{result_path}\n轨迹：{trace_path}")
    print("\n接下来评测：")
    print(f"  python evaluate.py {result_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
