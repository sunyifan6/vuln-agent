# -*- coding: utf-8 -*-
"""仓库工具：只读，三个。

search_code 会对命中行做类型标注（定义/调用/声明/注释），并按重要性排序，
让模型一眼分清"这是我手上这个函数本身"还是"别人在调它"。
"""

from __future__ import annotations

import os
import re
from pathlib import Path

MAX_RESULTS = 20
MAX_SCAN = 60
MAX_CHARS = 4000
MAX_FILE_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "vendor", "build", "dist", "__pycache__", ".github",
             "third_party", "testdata", "tests"}
CODE_SUFFIX = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
HEADER_SUFFIX = {".h", ".hpp", ".hh", ".hxx"}
_CTRL = {"if", "while", "for", "switch", "else", "do", "return", "case", "sizeof"}
_ORDER = {"定义": 0, "调用": 1, "声明": 2, "注释": 3, "引用": 4}


def safe_path(root: Path, rel: str) -> Path | None:
    p = (root / rel).resolve()
    return p if str(p).startswith(str(root.resolve())) else None


def _classify(path: Path, lines: list[str], i: int) -> str:
    s = lines[i].strip()
    if s.startswith(("//", "*", "/*")):
        return "注释"
    nxt = ""
    for j in range(i + 1, min(i + 4, len(lines))):
        if lines[j].strip():
            nxt = lines[j].strip()
            break
    head = s.split("(", 1)[0].strip().split()
    last = head[-1] if head else ""
    if (s.endswith("{") or nxt.startswith("{")) and "(" in s and last not in _CTRL:
        return "定义"
    if s.endswith(";"):
        return "声明" if path.suffix.lower() in HEADER_SUFFIX else "调用"
    return "引用"


def search_code(root: Path, pattern: str) -> str:
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return f"正则语法错误：{exc}"

    hits: list[tuple[int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in CODE_SUFFIX:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            for idx, line in enumerate(lines):
                if rx.search(line):
                    kind = _classify(p, lines, idx)
                    hits.append((_ORDER.get(kind, 9),
                                 f"{p.relative_to(root)}:{idx + 1} [{kind}] {line.strip()[:150]}"))
                    if len(hits) >= MAX_SCAN:
                        break
            if len(hits) >= MAX_SCAN:
                break
        if len(hits) >= MAX_SCAN:
            break

    if not hits:
        return f"没有匹配 {pattern!r}（换个写法，或这个词不在代码里）"

    hits.sort(key=lambda x: x[0])
    shown = [h[1] for h in hits[:MAX_RESULTS]]
    header = (f"命中 {len(hits)} 处，按重要性排序展示前 {len(shown)} 条：\n"
              "[定义]=函数体本身，[调用]=别处在用它，[声明]=头文件原型，[注释]可忽略")
    body = "\n".join(shown)
    if len(hits) > MAX_RESULTS:
        body += f"\n...（其余 {len(hits) - MAX_RESULTS} 条省略；想缩小范围请用更精确的正则）"
    return (header + "\n" + body)[:MAX_CHARS]


def read_file(root: Path, path: str, start: int = 1, end: int = 150) -> str:
    p = safe_path(root, path)
    if p is None:
        return f"路径越界：{path}"
    if not p.is_file():
        return f"文件不存在：{path}"
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return f"读取失败：{exc}"
    total = len(lines)
    start = max(1, start)
    end = min(total, max(start, end))
    body = "\n".join(f"{i:>5}  {lines[i - 1]}" for i in range(start, end + 1))
    return f"{path}（共 {total} 行，显示 {start}-{end}）\n{body}"[:MAX_CHARS]


def list_dir(root: Path, path: str = ".") -> str:
    p = safe_path(root, path)
    if p is None or not p.is_dir():
        return f"目录不存在：{path}"
    items = [f"{'[D]' if c.is_dir() else '   '} {c.name}" for c in sorted(p.iterdir())[:100]]
    return "\n".join(items)[:MAX_CHARS] or "空目录"


# ---------------------------------------------------------------- 工具定义

TOOLS = [
    {"type": "function", "function": {
        "name": "search_code",
        "description": "按正则搜索仓库代码，返回 路径:行号 [定义|调用|声明] 代码。找调用方、宏、类型定义时用。",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string", "description": "正则，例如 foo\\s*\\("}},
            "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "读取仓库中某个文件的指定行范围。",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "列出目录内容。",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                       "required": []}}},
]


def dispatch(root: Path | None, name: str, args: dict) -> str:
    if name == "search_code":
        return search_code(root, args.get("pattern", "")) if root else "仓库不可用"
    if name == "read_file":
        return read_file(root, args.get("path", ""), args.get("start", 1), args.get("end", 150)) \
            if root else "仓库不可用"
    if name == "list_dir":
        return list_dir(root, args.get("path", ".")) if root else "仓库不可用"
    return f"未知工具：{name}"
