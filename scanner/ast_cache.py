"""
ast_cache.py
------------
Persistent disk cache for nikic/php-parser AST trees.

Problem: every scan() call spawns a new PHP subprocess per file. On large
codebases (100+ files) and in CI loops, this wastes time re-parsing files
that haven't changed since the last run.

Solution: store each file's AST as JSON on disk, indexed by the SHA-256 of
the file's *content* (not its path or modification time). An unchanged file
hits the cache and skips the subprocess entirely.

Cache location:
    ~/.cache/wc-scanner/ast/                        (Linux/Mac)
    %LOCALAPPDATA%\\wc-scanner\\ast\\                (Windows)

Cache entry format:
    <sha256_hex[:16]>.json  ->  {"sha": "<full sha256>", "ast": [...]}

Fallback behavior: if the cache directory cannot be created or written to
(e.g. read-only filesystem, sandboxed CI runner), all operations silently
degrade to a no-op. The scanner still works correctly — just without the
speed benefit — because the in-memory cache in ASTEngine still applies
within a single run. No exception ever propagates out of this module.

Why content hash instead of mtime? mtime is unreliable across common
developer workflows: `git checkout`, `touch`, and file copies can all
change a file's mtime without changing its content (false cache miss) or
leave mtime unchanged after an edit in some filesystems (false cache hit,
which would silently serve stale results). Hashing the actual bytes is the
only invalidation strategy that is correct in all of these cases.

Cache invalidation:
  - Keyed on SHA-256 of file content (not mtime) — robust against touch,
    git checkout, and similar operations that don't change file bytes.
  - The --clear-cache CLI flag empties the entire cache directory.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path

# ── Cache directory resolution ────────────────────────────────────────────


def _cache_dir() -> Path:
    """
    Resolve the OS-appropriate cache directory and ensure it exists.

    Uses XDG_CACHE_HOME on Linux/Mac (falling back to ~/.cache) and
    LOCALAPPDATA on Windows, matching the conventions each platform expects
    for per-user application caches.
    """
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    d = base / "wc-scanner" / "ast"
    # If the directory can't be created (permissions, read-only FS), every
    # subsequent cache operation below will simply find no cache directory
    # and fail gracefully rather than raising.
    with contextlib.suppress(OSError):
        d.mkdir(parents=True, exist_ok=True)
    return d


_CACHE_DIR: Path = _cache_dir()


# ── Content hashing ─────────────────────────────────────────────────────────


def file_sha256(path: str) -> str | None:
    """Return the hex SHA-256 digest of a file's contents, or None on read failure."""
    try:
        data = Path(path).read_bytes()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


# ── Cache read/write ─────────────────────────────────────────────────────────


def cache_path(sha: str) -> Path:
    """
    Return the on-disk path for a cache entry keyed by SHA-256.

    Only the first 16 hex characters are used as the filename to keep
    directory listings short; the full hash is still stored inside the
    JSON payload and verified on read (see load_ast) to guard against the
    astronomically unlikely event of a 16-char prefix collision.
    """
    return _CACHE_DIR / f"{sha[:16]}.json"


def load_ast(file_path: str) -> list | None:
    """
    Attempt to load a previously cached AST for `file_path`.

    Returns the AST as a list of dicts on a cache hit, or None on any kind
    of miss: no cache file exists, the file changed since it was cached
    (verified via the full SHA stored inside the payload), or the cache
    entry is corrupted.
    """
    sha = file_sha256(file_path)
    if not sha:
        return None

    cp = cache_path(sha)
    if not cp.exists():
        return None

    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
        # Defense against a truncated-hash collision: only trust the entry
        # if its stored full SHA matches what we just computed.
        if data.get("sha") == sha:
            return list(data["ast"])
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return None


def store_ast(file_path: str, ast: list) -> None:
    """
    Persist an AST to disk, keyed by the SHA-256 of the source file's content.

    This is best-effort: any I/O failure (disk full, permissions, read-only
    filesystem) is swallowed silently. Caching is a performance optimization,
    never a correctness requirement, so it must never be able to break a scan.
    """
    sha = file_sha256(file_path)
    if not sha or not ast:
        return

    cp = cache_path(sha)
    with contextlib.suppress(OSError):
        cp.write_text(
            json.dumps({"sha": sha, "ast": ast}, separators=(",", ":")),
            encoding="utf-8",
        )


def clear_cache() -> int:
    """
    Delete every cached AST entry.

    Useful after a `composer update` in scanner/php/ that changes how the
    parser itself behaves, or simply to reclaim disk space. Returns the
    number of entries removed so the CLI can report it to the user.
    """
    removed = 0
    for f in _CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def cache_stats() -> dict:
    """Return entry count, total size in KB, and the cache directory path."""
    files = list(_CACHE_DIR.glob("*.json"))
    total_bytes = sum(f.stat().st_size for f in files if f.exists())
    return {
        "entries": len(files),
        "size_kb": round(total_bytes / 1024, 1),
        "cache_dir": str(_CACHE_DIR),
    }
