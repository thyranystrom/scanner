"""
ast_engine.py
-------------
Bridge between the Python scanner and nikic/php-parser (PHP).

Optimizations:
  - AST CACHE: each file is parsed only ONCE per scanning session,
    regardless of how many rule modules call analyze() on it.
  - BATCH PARSING: get_ast_batch() sends many file paths to a
    single PHP subprocess invocation (dump_ast.php --batch), instead of
    spawning one process per file. Profiling a real 202-file scan showed
    PHP subprocess startup (interpreter init, autoloading nikic/php-parser)
    dominating cold-scan time -- roughly 5.7s of a ~13s scan, almost all
    of it pure process-spawn overhead rather than actual parsing work.
    Batching amortizes that startup cost across many files at once.
    Chunked (default 50 files per subprocess call) so a single call still
    completes well within a bounded timeout even on very large plugins,
    rather than risking one enormous, slow, memory-heavy PHP process.
  - Timeout: scales with batch size so large chunks aren't cut off early.
  - Robust handling of Windows line endings (\\r\\n) in PHP's output.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from .ast_cache import load_ast, store_ast

# Files per batched PHP subprocess call. Small enough that one slow/huge
# file in a chunk doesn't blow the whole chunk's timeout budget, large
# enough to cut subprocess-spawn count by ~98% on a typical plugin.
_BATCH_SIZE = 50
_SECONDS_PER_FILE = 0.5
_MIN_BATCH_TIMEOUT = 8


class ASTEngine:
    """
    Runs dump_ast.php via subprocess and returns the AST as a Python list.
    Caches the result per absolute file path within the same Python process.
    """

    def __init__(self, php_script_path: str | None = None) -> None:
        if php_script_path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            php_script_path = os.path.join(base, "scanner", "php", "dump_ast.php")
        self.php_script_path = php_script_path
        # {abs_path: ast_or_None} — cleared between scan() calls via clear_cache()
        self._cache: dict[str, list[dict[str, Any]] | None] = {}

    def clear_cache(self) -> None:
        """Clear the cache between scanning sessions (called from main.scan())."""
        self._cache.clear()

    def get_ast(self, file_path: str) -> list[dict[str, Any]] | None:
        """
        Return the AST for file_path.
        Cache hit -> immediate answer, no subprocess spawned.
        Cache miss -> run PHP for this one file, store the result, return it.
        """
        abs_path = os.path.abspath(file_path)

        # Cache hit (including a stored None from a previous PHP failure)
        if abs_path in self._cache:
            return self._cache[abs_path]

        if not os.path.exists(abs_path):
            self._cache[abs_path] = None
            return None

        result = self._run_php(abs_path)
        self._cache[abs_path] = result
        return result

    def get_ast_batch(self, file_paths: list[str]) -> None:
        """
        Pre-warm the cache for many files using as few PHP subprocess
        spawns as possible, instead of one per file.

        Results are stored directly into self._cache (and the persistent
        disk cache) as a side effect; callers then use the normal get_ast()
        for each individual file, which becomes a pure cache lookup with no
        further subprocess overhead. This split keeps the batch-vs-single
        distinction entirely internal to ASTEngine -- every other module
        keeps calling get_ast() exactly as before.
        """
        # Resolve to absolute paths and skip anything already cached
        # (in-memory or on disk) or that doesn't exist on disk.
        to_parse: list[str] = []
        for fp in file_paths:
            abs_path = os.path.abspath(fp)
            if abs_path in self._cache:
                continue
            if not os.path.exists(abs_path):
                self._cache[abs_path] = None
                continue
            cached = load_ast(abs_path)
            if cached is not None:
                self._cache[abs_path] = cached
                continue
            to_parse.append(abs_path)

        for i in range(0, len(to_parse), _BATCH_SIZE):
            chunk = to_parse[i : i + _BATCH_SIZE]
            results = self._run_php_batch(chunk)
            for abs_path in chunk:
                ast = results.get(abs_path)
                self._cache[abs_path] = ast
                if ast is not None:
                    store_ast(abs_path, ast)

    def _run_php_batch(self, abs_paths: list[str]) -> dict[str, list[dict[str, Any]] | None]:
        """
        Parse many files in a single `php dump_ast.php --batch` call.
        Returns {abs_path: ast_or_None}; a parse failure for one file
        yields None for that path without affecting the rest of the batch.
        On any subprocess-level failure (timeout, PHP missing, malformed
        JSON), every path in this chunk falls back to None -- callers
        (get_ast_batch, and get_ast for anything not covered here) will
        simply miss the cache and, for get_ast() specifically, fall
        through to the single-file path as before.
        """
        stdin_data = "\n".join(abs_paths) + "\n"
        timeout = max(_MIN_BATCH_TIMEOUT, len(abs_paths) * _SECONDS_PER_FILE)
        try:
            proc = subprocess.run(
                ["php", self.php_script_path, "--batch"],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                return {}
            stdout = proc.stdout.replace("\r\n", "\n").replace("\r", "\n")
            raw: dict[str, Any] = json.loads(stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError):
            return {}
        return raw

    def _run_php(self, abs_path: str) -> list[dict[str, Any]] | None:
        """
        Run dump_ast.php for a single file and deserialize its JSON output.
        Checks the persistent disk cache (SHA-256) before spawning PHP.
        Stores the result in the disk cache for future scanner invocations.

        This single-file path still exists (rather than always batching)
        for callers needing exactly one file's AST outside of a full-scan
        context, e.g. inter-procedural resolution of a method defined in a
        file not part of the current batch.
        """
        # 1. Disk cache hit? (keyed by SHA-256 of the file's content)
        cached = load_ast(abs_path)
        if cached is not None:
            return cached

        # 2. Cache miss -> run the PHP subprocess
        try:
            proc = subprocess.run(
                ["php", self.php_script_path, abs_path],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if proc.returncode != 0:
                return None
            stdout = proc.stdout.replace("\r\n", "\n").replace("\r", "\n")
            ast: list[dict[str, Any]] = json.loads(stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError):
            return None

        # 3. Persist to disk cache for the next scanner run
        store_ast(abs_path, ast)
        return ast
