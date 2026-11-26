# -*- coding: utf-8 -*-
"""全局配置。所有路径相对于项目根目录。"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ============================================================================
# ↓↓↓  使用前请在这里填写你的 API key（到 https://platform.deepseek.com/api_keys 申请）
#
#     上传代码到 GitHub 之前，记得把下面这一行清空成 API_KEY = ""
#     否则你的密钥会随代码一起公开。
# ============================================================================
API_KEY = ""
# ============================================================================

# 官方数据（放在项目的上一级 workspace/dataset/dataset）
DATASET_DIR = Path(os.getenv("VULN_DATASET_DIR") or ROOT.parent / "dataset" / "dataset")
TEST_PATH = DATASET_DIR / "test.jsonl"
KB_PATH = DATASET_DIR / "knowledge.jsonl"
EVAL_SCRIPT = DATASET_DIR / "evaluation.py"

CACHE_DIR = ROOT / "cache"
OUT_DIR = ROOT / "out"

# LLM
BASE_URL = (os.getenv("VULN_BASE_URL") or "https://api.deepseek.com").rstrip("/")
MODEL = os.getenv("VULN_MODEL", "deepseek-flash")
TIMEOUT = int(os.getenv("VULN_TIMEOUT", "180"))
MAX_TOKENS = int(os.getenv("VULN_MAX_TOKENS", "4000"))
# 思考模式会把 max_tokens 全部消耗在 reasoning 上，正文为空（实测 8000 tokens 全烧光）。
# 这个任务是分类，不需要长思考，默认关闭。
THINKING = os.getenv("VULN_THINKING", "0") == "1"

# Agent
MAX_STEPS = int(os.getenv("VULN_MAX_STEPS", "3"))
MAX_TARBALL_MB = int(os.getenv("VULN_MAX_TARBALL_MB", "200"))

# RAG
TOP_K = int(os.getenv("VULN_TOP_K", "3"))
CASE_CHARS = 900

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

for _d in (CACHE_DIR, OUT_DIR):
    _d.mkdir(parents=True, exist_ok=True)
