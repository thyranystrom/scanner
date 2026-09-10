"""
input.py
--------
Fix notes:
  - wp_verify_nonce($_POST[...]) no longer fires WC-INPUT-002.
    The superglobal is consumed as a nonce token, not as data input.
  - Nonce presence lowers confidence but does NOT skip lines.
  - Confidence is computed via confidence.Scorer.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..confidence import S, Scorer, score_input_direct, score_sql
from ..dataflow import analyze, resolve_source_file
from ..fp_reducer import (
    phpcs_suppresses,
)
from ..models import Finding
from ..sanitizers import ALL_SANITIZERS as _CANONICAL_SANITIZERS
from ..utils import snippet

# Canonical list — imported from sanitizers.py
SANITIZERS = _CANONICAL_SANITIZERS

_NONCE = re.compile(r"wp_verify_nonce|check_admin_referer|check_ajax_referer")
# A line where $_POST/GET appears inside a nonce function call argument
_NONCE_ARG = re.compile(
    r"\b(wp_verify_nonce|check_admin_referer|check_ajax_referer)"
    r"\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
)
_DIRECT_GET = re.compile(r"\$_GET\s*\[")
_DIRECT_POST = re.compile(r"\$_POST\s*\[")
_DIRECT_REQUEST = re.compile(r"\$_REQUEST\s*\[")


# A single compiled alternation, built once at import time, checked with
# one regex search instead of doing up to ~40 separate Python-level
# substring checks per line (this function runs once per line of every
# scanned file, so the per-line cost compounds fast on a large codebase).
_SANITIZER_RE = re.compile("|".join(re.escape(s) for s in SANITIZERS))


def _line_sanitized(line: str) -> bool:
    return bool(_SANITIZER_RE.search(line))


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith("//") or s.startswith("#") or s.startswith("*")


def scan_input(
    file_path: str | Path,
    code: str | None = None,
    project=None,
    **kwargs,
) -> list[Finding]:
    findings: list[Finding] = []
    path_str = str(file_path)

    actual_code = code or ""
    if not actual_code and Path(path_str).is_file():
        try:
            actual_code = Path(path_str).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            actual_code = ""

    lines = actual_code.splitlines()

    has_nonce = bool(_NONCE.search(actual_code))
    sanitizer_in_file = any(s in actual_code for s in SANITIZERS)

    for idx, line in enumerate(lines, start=1):
        if _is_comment(line):
            continue
        if _line_sanitized(line):
            continue
        if "isset(" in line or "empty(" in line:
            continue
        # Superglobal used as nonce argument – not a data input finding
        if _NONCE_ARG.search(line):
            continue
        # phpcs:ignore anywhere on this line or nearby → developer explicitly OK'd it
        if phpcs_suppresses(lines, idx):
            continue
        # Transformation wrappers: the raw superglobal is intentionally consumed
        # by json_decode/base64_decode/unserialize – not "unsanitized input" in
        # the traditional sense. The developer is working with structured raw data.
        if re.search(
            r"\b(json_decode|base64_decode|unserialize|hex2bin|pack|unpack)\s*\(",
            line,
        ):
            continue

        def _add(rule_id: str, title: str, source: str, line_no: int = idx) -> None:
            conf = score_input_direct(
                nonce_present=has_nonce,
                sanitizer_in_scope=sanitizer_in_file,
            )
            notes = []
            if has_nonce:
                notes.append("nonce present -- CSRF-protected but input is still unsanitized")
            if sanitizer_in_file:
                notes.append("a sanitizer exists in this file -- verify it wraps THIS value")
            msg = (
                f"Direct {source} access without sanitization. "
                "Wrap with sanitize_text_field(), absint() or similar."
            )
            if notes:
                msg += " NOTE: " + "; ".join(notes) + "."
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity="LOW",
                    message=msg,
                    file=path_str,
                    line=line_no,
                    owasp="A05:2025-Injection",
                    confidence=conf,
                    evidence=snippet(lines, line_no),
                    source=source,
                )
            )

        if _DIRECT_GET.search(line):
            _add("WC-INPUT-001", "Unsanitized $_GET Access", "$_GET")
        if _DIRECT_POST.search(line):
            _add("WC-INPUT-002", "Unsanitized $_POST Access", "$_POST")
        if _DIRECT_REQUEST.search(line):
            _add("WC-INPUT-003", "Unsanitized $_REQUEST Access", "$_REQUEST")

    # Taint-dataflow
    df_results = analyze(
        actual_code, source_file=resolve_source_file(path_str, project), project=project
    )
    seen_lines: set[int] = {f.line for f in findings}

    for r in df_results:
        if getattr(r, "is_sanitized", False):
            continue
        sink_line = getattr(r, "sink_line", 1)
        if sink_line in seen_lines:
            continue

        if getattr(r, "sink_type", "") == "sql":
            conf = score_sql(
                taint_chain=True,
                prepare_nearby=False,
                direct_input=bool(getattr(r, "superglobal", "")),
            )
            if has_nonce:
                conf = Scorer(base=conf).add(S.NONCE_PRESENT).score()
            findings.append(
                Finding(
                    rule_id="WC-SQL-001",
                    title="Tainted Variable Reaches SQL Sink",
                    severity="HIGH",
                    message=(
                        f"${getattr(r, 'var_name', 'var')} was tainted from "
                        f"{getattr(r, 'superglobal', 'input')} "
                        f"(line {getattr(r, 'taint_line', '?')}) and reaches a "
                        f"database call without $wpdb->prepare() on line {sink_line}."
                    ),
                    file=path_str,
                    line=sink_line,
                    owasp="A05:2025-Injection",
                    confidence=conf,
                    evidence=snippet(lines, sink_line),
                    flow_type="taint",
                    taint_line=getattr(r, "taint_line", None),
                )
            )
        else:
            conf = (
                Scorer(base=0.40)
                .add(S.TAINT_CHAIN)
                .add(*([S.NONCE_PRESENT] if has_nonce else []))
                .score()
            )
            findings.append(
                Finding(
                    rule_id="WC-XSS-001",
                    title="Tainted Variable Reaches Output Sink",
                    severity="MEDIUM",
                    message=(
                        f"${getattr(r, 'var_name', 'var')} was tainted from "
                        f"{getattr(r, 'superglobal', 'input')} "
                        f"(line {getattr(r, 'taint_line', '?')}) and is output without "
                        f"escaping on line {sink_line}. Use esc_html() or esc_attr()."
                    ),
                    file=path_str,
                    line=sink_line,
                    owasp="A05:2025-Injection",
                    confidence=conf,
                    evidence=snippet(lines, sink_line),
                    flow_type="taint",
                    taint_line=getattr(r, "taint_line", None),
                )
            )
        seen_lines.add(sink_line)

    return findings
