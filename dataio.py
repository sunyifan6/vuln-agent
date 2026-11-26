# -*- coding: utf-8 -*-
"""数据层：读官方数据集，解析提交链接，解析父提交（带磁盘缓存）。

官方字段（test.jsonl）：
    idx          整数，提交结果时用它
    commit_url   修复提交的 GitHub 链接
    target       0/1 标签：1=漏洞版、0=修复版
    func         函数源码

注意：target 就是标签，绝对不能进 prompt；它只用来①选哪个版本的快照 ②本地评分。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import config

COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
PARENT_CACHE = config.CACHE_DIR / "parents.json"


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"文件不存在：{path}")
    rows = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def parse_commit_url(url: str) -> tuple[str, str, str] | None:
    m = COMMIT_RE.search(url or "")
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3).lower()


# ---------------------------------------------------------------- 父提交

def _load_parent_cache() -> dict:
    if PARENT_CACHE.exists():
        try:
            return json.loads(PARENT_CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_parent_cache(cache: dict) -> None:
    PARENT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    PARENT_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=0), encoding="utf-8")


def parent_sha(owner: str, repo: str, sha: str) -> str:
    """查父提交。结果落盘缓存，重复运行不再请求 API。"""
    cache = _load_parent_cache()
    key = f"{owner}/{repo}@{sha}"
    if key in cache:
        return cache[key]

    import urllib.error
    import urllib.request

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vuln-agent/1.0"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()[:200].decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {exc.code}（{owner}/{repo}）：{body}") from None

    parents = data.get("parents") or []
    if not parents:
        raise RuntimeError(f"{owner}/{repo}@{sha[:8]} 没有父提交")
    parent = parents[0]["sha"]
    cache[key] = parent
    _save_parent_cache(cache)
    return parent


# ---------------------------------------------------------------- 样本

def load_test(resolve_sha: bool = False) -> list[dict]:
    """官方测试集 → 内部格式。

    内部字段：
        idx    原样
        label  官方 target（0/1）
        func   函数源码
        repo   owner/repo
        sha    该样本对应版本的 sha（label=1 取父提交，label=0 取提交本身）
        note   解析失败的原因

    resolve_sha=False 时只解析 repo，不查父提交 —— baseline / rag 模式不需要仓库，
    可以完全离线跑完 300 条，避免 150 次 GitHub API 调用。
    """
    rows = load_jsonl(config.TEST_PATH)
    out = []
    for r in rows:
        idx = r.get("idx")
        label = int(r.get("target"))
        item = {
            "idx": idx,
            "label": label,
            "func": r.get("func") or "",
            "commit_url": r.get("commit_url") or "",
            "repo": None,
            "sha": None,
            "note": "",
        }
        parsed = parse_commit_url(item["commit_url"])
        if not parsed:
            item["note"] = "commit_url 解析失败"
            out.append(item)
            continue
        owner, repo, sha = parsed
        item["repo"] = f"{owner}/{repo}"
        if not resolve_sha:
            out.append(item)
            continue
        try:
            item["sha"] = parent_sha(owner, repo, sha) if label == 1 else sha
        except Exception as exc:  # noqa: BLE001
            item["note"] = f"父提交解析失败：{exc}"
        out.append(item)
    return out


def load_kb() -> list[dict]:
    """知识库 → 检索文档。只索引漏洞版（target=1）。

    实测对比：把"漏洞版+修复版"成对塞给模型，反而让 P-C 从 20% 掉到 7%
    ——模型看到修复版的差异后倾向于"找出剩余问题"，判 1 变多，P-V 暴涨。
    所以 RAG 只提供漏洞侧的同类案例，让模型把它当"缺陷模式参考"。
    """
    rows = load_jsonl(config.KB_PATH)
    docs = []
    for r in rows:
        if int(r.get("target", 0)) != 1:
            continue
        cwe = r.get("cwe")
        if isinstance(cwe, list):
            cwe = " ".join(x for x in cwe if x)
        docs.append({
            "cve": r.get("cve") or "",
            "cwe": cwe or "",
            "cve_desc": (r.get("cve_desc") or "")[:300],
            "text": "\n".join([
                r.get("project") or "",
                cwe or "",
                r.get("cve") or "",
                (r.get("cve_desc") or "")[:400],
                (r.get("commit_message") or "")[:200],
                (r.get("func") or "")[:1500],
            ]),
            "func": (r.get("func") or "")[: config.CASE_CHARS],
        })
    return docs
