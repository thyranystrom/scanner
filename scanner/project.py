"""project.py – cross-file class-aware symbol index."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .utils import php_files

_FUNC = re.compile(
    r"(?:public|private|protected|static|\s)*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
    re.I | re.M,
)
_CLASS = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.I)


_BRACE = re.compile(r"[{}]")


def _extract_body(text: str, brace_pos: int, max_chars: int = 16000) -> str:
    """
    Extract a brace-matched block starting at `brace_pos`. See
    deep.py's identical function for why this uses a compiled regex to
    jump between brace positions instead of a per-character while-loop
    (~5x faster on realistic function bodies, byte-identical output).
    This file had its own independent copy of the same logic (a
    different max_chars default is the only real difference), so it
    needed the same fix applied separately.
    """
    end = min(len(text), brace_pos + max_chars)
    depth = 0
    for m in _BRACE.finditer(text, brace_pos, end):
        if m.group() == "{":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return text[brace_pos : m.end()]
    return text[brace_pos:end]


@dataclass
class Symbol:
    name: str
    file: str
    body: str
    start_line: int
    class_name: str | None = None


@dataclass
class ProjectIndex:
    symbols: dict[str, list[Symbol]] = field(default_factory=dict)
    by_class: dict[str, dict[str, Symbol]] = field(default_factory=dict)
    file_text: dict[str, str] = field(default_factory=dict)
    root: Path | None = None

    def add(self, sym: Symbol) -> None:
        self.symbols.setdefault(sym.name, []).append(sym)
        if sym.class_name:
            self.by_class.setdefault(sym.class_name, {})[sym.name] = sym

    def lookup(self, name: str, prefer_file: str | None = None, prefer_class: str | None = None):
        if prefer_class and prefer_class in self.by_class and name in self.by_class[prefer_class]:
            return self.by_class[prefer_class][name]
        hits = self.symbols.get(name) or []
        if not hits:
            return None
        if prefer_file:
            for h in hits:
                if prefer_file.replace("\\", "/") in h.file.replace("\\", "/"):
                    return h
        for h in hits:
            if any(t in (h.class_name or "").lower() for t in ("jwt", "token", "oauth", "auth")):
                return h
        return hits[0]

    def bodies_for(self, name: str, prefer_file=None, prefer_class=None, limit=3):
        if prefer_class and prefer_class in self.by_class and name in self.by_class[prefer_class]:
            return [self.by_class[prefer_class][name].body]
        hits = list(self.symbols.get(name) or [])
        hits.sort(
            key=lambda s: (
                0 if any(t in (s.class_name or "").lower() for t in ("jwt", "token")) else 1
            )
        )
        return [h.body for h in hits[:limit]]

    def class_names_matching(self, *substrings: str):
        return [cn for cn in self.by_class if any(s.lower() in cn.lower() for s in substrings)]


def build_project_index(root: Path) -> ProjectIndex:
    idx = ProjectIndex(root=root)
    for path in php_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        idx.file_text[rel] = text
        class_ranges = [(m.start(), m.group(1)) for m in _CLASS.finditer(text)]

        def class_at(pos, _ranges=class_ranges):
            best = None
            for start, name in _ranges:
                if start <= pos:
                    best = name
            return best

        for m in _FUNC.finditer(text):
            brace = m.end() - 1
            idx.add(
                Symbol(
                    name=m.group(1),
                    file=rel,
                    body=_extract_body(text, brace),
                    start_line=text.count("\n", 0, m.start()) + 1,
                    class_name=class_at(m.start()),
                )
            )
    return idx
