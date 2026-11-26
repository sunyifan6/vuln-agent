# -*- coding: utf-8 -*-
"""仓库快照：按 sha 下载 tarball 并解压，不带 .git。

两个关键点：
  1. 用 codeload 的 tar.gz，而不是 git clone —— 后者带完整历史，
     一条 git log 就能看到修复 diff，等于泄题。
  2. 提供 cleanup —— 处理完立刻删，否则 300 条样本会把磁盘撑爆
     （测试集里 tensorflow 占 46%，单仓就上百 MB）。
"""

from __future__ import annotations

import shutil
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import config


class RepoError(RuntimeError):
    pass


def _tarball_path(owner: str, repo: str, sha: str) -> Path:
    cache = config.CACHE_DIR / "tars"
    cache.mkdir(parents=True, exist_ok=True)
    return cache / f"{owner}_{repo}@{sha[:12]}.tar.gz"


def download(owner: str, repo: str, sha: str) -> Path:
    dest = _tarball_path(owner, repo, sha)
    if dest.exists() and dest.stat().st_size > 0:
        return dest

    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}"
    limit = config.MAX_TARBALL_MB * 1024 * 1024
    tmp = dest.with_name(dest.name + ".part")
    total = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vuln-agent/1.0"})
        with urllib.request.urlopen(req, timeout=180) as resp, open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise RepoError(f"{owner}/{repo} 超过 {config.MAX_TARBALL_MB} MB")
                fh.write(chunk)
    except urllib.error.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise RepoError(f"下载失败 HTTP {exc.code}") from None
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(dest)
    return dest


def unpack(owner: str, repo: str, sha: str) -> Path:
    dest = config.CACHE_DIR / "repos" / f"{owner}_{repo}" / sha[:12]
    if (dest / ".ready").exists():
        return dest

    tar = download(owner, repo, sha)
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent / f".unpack-{sha[:12]}"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    try:
        with tarfile.open(tar, "r:gz") as tf:
            try:
                tf.extractall(staging, filter="data")
            except TypeError:
                tf.extractall(staging)
        tops = [p for p in staging.iterdir() if p.is_dir()]
        if len(tops) != 1:
            raise RepoError(f"压缩包结构异常：{len(tops)} 个顶层目录")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        tops[0].rename(dest)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    (dest / ".ready").write_text(sha, encoding="utf-8")
    return dest


def ensure(sample: dict) -> Path:
    if not sample.get("repo") or not sample.get("sha"):
        raise RepoError("样本缺少 repo 或 sha")
    owner, repo = sample["repo"].split("/", 1)
    return unpack(owner, repo, sample["sha"])


def cleanup(sample: dict) -> None:
    """删掉解压后的仓库目录（tarball 保留，复用更快）。"""
    if not sample.get("repo") or not sample.get("sha"):
        return
    owner, repo = sample["repo"].split("/", 1)
    dest = config.CACHE_DIR / "repos" / f"{owner}_{repo}" / sample["sha"][:12]
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

