"""
output.py
---------
FIX: _ECHO used to use re.S (dotall mode), which let "echo" inside a
     // comment bridge across to a $var on a following line, producing
     false positives.
     Now: no re.S, and _emit explicitly guards against comment lines.

Sinks covered: echo, print(), printf(), vprintf(), fprintf(), heredoc.
"""

from __future__ import annotations

import re

from ..confidence import score_output
from ..dataflow import analyze, resolve_source_file
from ..fp_reducer import (
    _PHPCS_OUTPUT_KEYS,
    extract_function_scope,
    phpcs_suppresses,
    sanitizer_in_scope,
)
from ..models import Finding
from ..sanitizers import ALL_SANITIZERS as _ALL_SANITIZERS
from ..sanitizers import OUTPUT_SAFE as _OUTPUT_SAFE
from ..utils import line_number, snippet

# -- Escape functions that neutralize output ----------------------------------
# Built FROM the canonical OUTPUT_SAFE set (sanitizers.py) instead of a
# separately hardcoded list of names. A prior version of this pattern was
# its own hand-maintained list that had drifted from sanitizers.py --
# `json_encode` was present but `wp_json_encode` was not, so
# `echo wp_json_encode($response);` (the standard, safe way to end a
# WordPress AJAX handler) was incorrectly flagged as unescaped output.
# Deriving the pattern from OUTPUT_SAFE instead makes this the single
# source of truth sanitizers.py's own docstring already promises, while
# staying narrower than the full ALL_SANITIZERS set (see OUTPUT_SAFE's
# docstring for why that distinction matters).
_ESCAPE = re.compile(r"\b(" + "|".join(sorted(_OUTPUT_SAFE)) + r")\s*\(")

# ── phpcs:ignore ──────────────────────────────────────────────────────────────
_PHPCS_KEYS = (
    "escape",
    "xss",
    "output",
    "user input",
    "does not contain user",
    "not user",
    "body",
)

# ── Sink patterns ────────────────────────────────────────────────────────────

# echo – NO re.S flag: prevents "echo" inside // comments from bridging
# to $var on subsequent lines (was causing false positives on comment lines).
# [^;\n] ensures we stay on one line.
_ECHO = re.compile(
    r"\becho\s+"
    r"(?:"
    r'["\'](?:[^"\'\\]|\\.)*\$[A-Za-z_]\w*(?:[^"\'\\]|\\.)*["\']'  # "...$var..."
    r"|\$[A-Za-z_]\w*"  # $var
    r"|[^;\n]+\$[A-Za-z_]\w+"  # $a . $b
    r")"
    r"[^;\n]*;"
)

# print / printf / vprintf / fprintf with at least one variable in the arguments
_PRINT_FNS = re.compile(r"\b(print|printf|vprintf|fprintf)\s*\([^)]*\$[A-Za-z_]\w*")

# Heredoc opening and closing markers
_HEREDOC_OPEN = re.compile(r"<<<\s*['\"]?(\w+)['\"]?")


def _phpcs_suppress(lines: list[str], line_no: int) -> bool:
    """Delegates to fp_reducer.phpcs_suppresses() with output-specific keywords."""
    return phpcs_suppresses(lines, line_no, _PHPCS_OUTPUT_KEYS)


# PHP's sprintf/printf positional format specifiers -- e.g. %1$s, %2$d,
# %10$x. These are matched by a naive `\$[A-Za-z_]\w*` scan (the trailing
# "$s"/"$d"/etc. looks exactly like a one-character variable name), even
# though there is no variable at all: it's format-string syntax consumed
# entirely by sprintf()/printf() itself. Found as a real false positive:
# `printf('...%1$s...%2$s...', esc_attr($a), esc_attr($b))` was flagged
# with a phantom "$s" variable despite every real argument already being
# properly escaped.
_SPRINTF_POSITIONAL = re.compile(r"%\d+\$[a-zA-Z]")


def _vars_in(fragment: str) -> list[str]:
    fragment = _SPRINTF_POSITIONAL.sub("", fragment)
    return re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", fragment)


# Matches `$condition ? 'literal' : 'literal'` where BOTH ternary branches
# are plain quoted strings with no variable interpolation inside them.
# Used to recognize a real false-positive class: a boolean-style variable
# used purely to SELECT between two fixed, safe strings never has its own
# value embedded in the output at all, so escaping it is meaningless --
# unlike `echo $x ? $x : 'default';`, where $x's actual value can reach
# the page when the condition is true. Found via a real example:
# `echo $is_connected ? '<div id="a"></div>' : '<div id="b"></div>';`
_TERNARY_LITERAL_BRANCHES = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\s*\?\s*"
    r"(?P<a>'[^'$]*'|\"[^\"$]*\")\s*:\s*"
    r"(?P<b>'[^'$]*'|\"[^\"$]*\")"
)


def _condition_only_vars(fragment: str) -> set[str]:
    """
    Return variable names that appear ONLY as a ternary condition whose
    both branches are variable-free string literals -- see
    _TERNARY_LITERAL_BRANCHES's docstring for why these don't need escaping.
    """
    return {m.group(1) for m in _TERNARY_LITERAL_BRANCHES.finditer(fragment)}


def _is_comment_line(line: str) -> bool:
    """Return True if the line is purely a comment (// # * /*)."""
    s = line.lstrip()
    return s.startswith("//") or s.startswith("#") or s.startswith("*") or s.startswith("/*")


def scan_output(path, text, project=None) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    # Dataflow for taint information
    flow_results = analyze(
        text, source_file=resolve_source_file(str(path), project), project=project
    )
    tainted_vars: set[str] = {fr.var for fr in flow_results if fr.sink_type == "output"}
    taint_map: dict[str, int] = {
        fr.var: fr.taint_line for fr in flow_results if fr.sink_type == "output"
    }
    # Variables assigned from string literals (lower risk)
    literal_vars: set[str] = set(re.findall(r"\$([A-Za-z_]\w*)\s*=\s*['\"][^'\"]*['\"]", text))

    seen_lines: set[int] = set()

    def _emit(line_no: int, sink_label: str, var_names: list[str]) -> None:
        if line_no in seen_lines or not var_names:
            return
        line_text = lines[line_no - 1] if line_no <= len(lines) else ""

        # Guard: never flag comment lines (belt-and-suspenders vs regex gaps)
        if _is_comment_line(line_text):
            return
        # Escape on same line → safe
        if _ESCAPE.search(line_text):
            return
        # phpcs:ignore anywhere on this line or the lines just above → suppress
        if _phpcs_suppress(lines, line_no):
            return
        # Broader sanitizer check: scan the entire enclosing function scope,
        # not just the immediate line. A sanitizer in the same function that
        # wraps our variable reduces the risk substantially.
        _scope = extract_function_scope(lines, line_no)
        _best_var_for_scope = var_names[0] if var_names else ""
        if _best_var_for_scope and sanitizer_in_scope(_scope, _best_var_for_scope, _ALL_SANITIZERS):
            return

        # Choose "best" variable: tainted > unknown > literal
        best, is_tainted = None, False
        for v in var_names:
            if v in tainted_vars:
                best, is_tainted = v, True
                break
        if best is None:
            best = var_names[0]
        is_literal = best in literal_vars

        conf, sev = score_output(
            taint_chain=is_tainted,
            escape_on_line=bool(_ESCAPE.search(line_text)),
            literal_assign=is_literal,
            phpcs_suppress=False,
            nonce_present=False,
        )

        if sev == "INFO":
            sev = "LOW"

        findings.append(
            Finding(
                rule_id="WC-OUTPUT-001",
                severity=sev,
                title=(
                    f"Tainted variable ${best} in {sink_label}"
                    if is_tainted
                    else f"Unescaped variable ${best} in {sink_label}"
                ),
                file=str(path),
                line=line_no,
                message="Review whether the value is escaped for its output context.",
                owasp="A05:2025-Injection",
                confidence=conf,
                evidence=snippet(lines, line_no),
                source=f"${best}",
                sink=sink_label,
                flow_type="taint" if is_tainted else None,
                taint_line=taint_map.get(best) if is_tainted else None,
            )
        )
        seen_lines.add(line_no)

    # ── 1. Heredoc (first – reserves its line so echo scanner skips it) ──────
    heredoc_lines: set[int] = set()
    pos = 0
    while True:
        mo = _HEREDOC_OPEN.search(text, pos)
        if not mo:
            break
        marker = mo.group(1)
        if "'" in mo.group(0):  # nowdoc – no interpolation
            pos = mo.end()
            continue
        end_pat = re.compile(r"^" + re.escape(marker) + r"\s*;", re.M)
        me = end_pat.search(text, mo.end())
        if not me:
            pos = mo.end()
            continue
        body_vars = _vars_in(text[mo.end() : me.start()])
        open_line = line_number(text, mo.start())
        heredoc_lines.add(open_line)
        if body_vars:
            _emit(open_line, "heredoc", body_vars)
        pos = me.end()

    # ── 2. echo ──────────────────────────────────────────────────────────────
    for m in _ECHO.finditer(text):
        line_no = line_number(text, m.start())
        if line_no in heredoc_lines:
            continue
        fragment = m.group(0)
        var_names = _vars_in(fragment)
        if not var_names:
            continue
        # Drop variables that only appear as a ternary condition selecting
        # between two variable-free string literals (see _condition_only_vars).
        condition_only = _condition_only_vars(fragment)
        var_names = [v for v in var_names if v not in condition_only]
        if not var_names:
            continue
        _emit(line_no, "echo", var_names)

    # ── 3. print / printf / vprintf / fprintf ─────────────────────────────────
    for m in _PRINT_FNS.finditer(text):
        line_no = line_number(text, m.start())
        call_window = text[m.start() : m.start() + 300]
        var_names = _vars_in(call_window)
        condition_only = _condition_only_vars(call_window)
        var_names = [v for v in var_names if v not in condition_only]
        if not var_names:
            continue
        _emit(line_no, m.group(1) + "()", var_names)

    return findings
