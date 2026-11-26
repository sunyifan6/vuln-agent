# -*- coding: utf-8 -*-
"""RAG 检索层：BM25，零依赖。

知识库 = knowledge.jsonl 的漏洞版（3789 条），已确认与测试集零重叠。
检索返回"历史上长得像的漏洞函数"，附 CWE 和 CVE 描述作为语义信号。
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

import config

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+")
SPLIT_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+")

# C/C++ 关键字：几乎每段代码都有，没有区分度
STOPWORDS = {
    "int", "char", "void", "long", "short", "float", "double", "unsigned", "signed",
    "const", "static", "struct", "union", "enum", "typedef", "extern", "inline",
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "return", "goto", "sizeof", "default", "register", "volatile", "auto",
    "null", "nullptr", "true", "false", "include", "define", "ifdef", "endif",
    "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int32_t",
    "int64_t", "guint", "gint", "gboolean", "gchar", "gpointer",
}

INDEX_PATH = config.CACHE_DIR / "bm25.json"


def tokenize(code: str) -> list[str]:
    out: list[str] = []
    for tok in TOKEN_RE.findall(code or ""):
        low = tok.lower()
        if low in STOPWORDS or len(low) == 1:
            continue
        out.append(low)
        parts = SPLIT_RE.findall(tok)
        if len(parts) > 1:
            out.extend(p.lower() for p in parts if p.lower() not in STOPWORDS and len(p) > 1)
    return out


class BM25:
    def __init__(self, docs: list[dict], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self.tfs: list[Counter] = []
        self.dls: list[int] = []
        df: Counter = Counter()
        for d in docs:
            tf = Counter(tokenize(d.get("text", "")))
            self.tfs.append(tf)
            self.dls.append(sum(tf.values()))
            for term in tf:
                df[term] += 1
        self.df = df
        self.N = len(docs)
        self.avgdl = (sum(self.dls) / self.N) if self.N else 0.0

    def _idf(self, term: str) -> float:
        df = self.df.get(term, 0)
        return math.log(1 + (self.N - df + 0.5) / (df + 0.5))

    def search(self, query: str, k: int = 3) -> list[tuple[float, dict]]:
        terms = set(tokenize(query))
        if not terms or not self.N:
            return []
        scored: list[tuple[float, int]] = []
        for i, tf in enumerate(self.tfs):
            dl = self.dls[i] or 1
            s = 0.0
            for term in terms:
                f = tf.get(term, 0)
                if f:
                    s += self._idf(term) * f * (self.k1 + 1) / (
                        f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            if s > 0:
                scored.append((s, i))
        scored.sort(reverse=True)
        return [(s, self.docs[i]) for s, i in scored[:k]]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"docs": self.docs}, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "BM25":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data["docs"])


def get_index(docs: list[dict] | None = None, rebuild: bool = False) -> BM25:
    """有缓存就用缓存；--rebuild 或缓存缺失时重建。"""
    if not rebuild and INDEX_PATH.exists():
        return BM25.load(INDEX_PATH)
    if docs is None:
        import dataio
        docs = dataio.load_kb()
    idx = BM25(docs)
    idx.save(INDEX_PATH)
    return idx
