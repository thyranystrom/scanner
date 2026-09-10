"""
fp_reducer.py
-------------
Shared helper functions for reducing false positives across all rule modules.

Guiding principle: search as broadly as possible — the whole enclosing
function or class scope, not just a couple of neighboring lines — before
deciding whether a finding is genuine or has evidence against it
(a sanitizer call, a nonce check, a phpcs:ignore directive, a constant
source, etc.). A narrow, line-local check misses protection that a
developer legitimately placed a few lines away.

Used by: input.py, output.py, owasp_top10.py, sql.py
"""

from __future__ import annotations

import functools
import re

# ── phpcs:ignore ───────────────────────────────────────────────────────────

_PHPCS_OUTPUT_KEYS = frozenset(
    {
        "escape",
        "xss",
        "output",
        "user input",
        "does not contain user",
        "not user",
        "body",
        "wordpress.security",
    }
)
_PHPCS_INPUT_KEYS = frozenset({"nonce", "csrf", "sanitiz", "input", "validated"})
_PHPCS_GENERIC = frozenset({"phpcs:ignore", "phpcs:disable"})


def phpcs_suppresses(lines: list[str], line_no: int, keys: frozenset | None = None) -> bool:
    """
    True if a phpcs:ignore/disable directive covers this line, checking:
      - the SAME line (inline comment: echo $x; // phpcs:ignore XSS)
      - or any of the THREE lines above it

    Suppression logic:
      1. A bare "phpcs:ignore" with no keyword -> always suppresses.
         The developer has explicitly signed off on this line with no
         qualification.
         E.g.:  echo $x; // phpcs:ignore
      2. "phpcs:ignore Key1,Key2" -> suppresses if any of `keys`
         matches one of the given keywords.
         E.g.:  echo $x; // phpcs:ignore WordPress.Security.EscapeOutput
      3. No phpcs directive at all -> False.
    """
    check_range = [line_no - 1, line_no - 2, line_no - 3, line_no - 4]
    for i in check_range:
        if 0 <= i < len(lines):
            low = lines[i].lower()
            if "phpcs:ignore" in low or "phpcs:disable" in low:
                # Find whatever text follows the phpcs:ignore/disable marker
                after = ""
                for marker in ("phpcs:ignore", "phpcs:disable"):
                    pos = low.find(marker)
                    if pos >= 0:
                        after = low[pos + len(marker) :].strip()
                        break

                # No keyword at all -> a bare ignore always suppresses
                if not after or after.startswith("--") or after.startswith("//"):
                    return True

                # With a keyword present: match against `keys` if the
                # caller supplied a restriction, otherwise any keyword
                # suppresses (no restriction = accept all rule keywords).
                if keys is None:
                    return True
                if any(k in after for k in keys):
                    return True
    return False


# ── Function/method scope extraction ────────────────────────────────────────


def extract_function_scope(lines: list[str], line_no: int, max_lines: int = 80) -> str:
    """
    Return the source text of the function or method enclosing line_no.

    Searches backward for the nearest 'function' keyword, then forward to
    the matching closing brace (tracked via simple brace-depth counting,
    which is sufficient here since we only need approximate scope
    boundaries, not a syntactically perfect one). The search is capped at
    max_lines in each direction to keep this fast even inside
    pathologically long functions.

    This is what lets sanitizer_in_scope() and nonce_in_scope() find
    protection anywhere in the enclosing function, not just within a
    couple of lines of the finding.
    """
    start = max(0, line_no - 1 - max_lines)
    end = min(len(lines), line_no + max_lines)

    # Search backward for the function/method declaration line.
    func_start = start
    for i in range(line_no - 1, start - 1, -1):
        if re.search(r"\bfunction\b", lines[i]):
            func_start = i
            break

    # Search forward for the matching closing brace via depth counting.
    depth = 0
    func_end = end
    for i in range(func_start, end):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > func_start:
            func_end = i + 1
            break

    return "\n".join(lines[func_start:func_end])


# ── Sanitizer presence within scope ─────────────────────────────────────────


@functools.lru_cache(maxsize=2048)
def _compiled_sanitizer_pattern(var_name: str, sanitizers: frozenset) -> re.Pattern:
    """
    Build and cache the sanitizer-wrapping regex for one (var_name,
    sanitizers) pair.

    Before this cache existed, sanitizer_in_scope() rebuilt the FULL
    ~40-way sanitizer alternation from scratch and recompiled it on every
    call, with a different var_name interpolated in each time -- this
    defeats Python's own internal re.compile() cache (which keys on the
    exact pattern string) since the string differs per call. Profiling a
    real 202-file scan showed this as roughly a million redundant
    re._compile() calls. Common variable names (`$id`, `$data`, `$value`,
    etc.) recur constantly across a large codebase, so caching by
    (var_name, sanitizers) turns nearly all of those into cache hits.
    """
    return re.compile(
        r"(" + "|".join(re.escape(s) for s in sanitizers) + r")\s*\("
        r"[^)]*\$" + re.escape(var_name),
        re.I,
    )


def sanitizer_in_scope(scope_text: str, var_name: str, sanitizers: frozenset) -> bool:
    """
    Return True if var_name is explicitly sanitized somewhere in scope_text.

    Looks for patterns like sanitizer($var) or $var = sanitizer(...).
    Searching within a specific function scope (rather than the whole
    file) avoids false negatives where a same-named variable is sanitized
    in a completely unrelated function.
    """
    pattern = _compiled_sanitizer_pattern(var_name, sanitizers)
    return bool(pattern.search(scope_text))


def nonce_in_scope(scope_text: str) -> bool:
    """True if a nonce check exists somewhere in the function scope."""
    return bool(
        re.search(
            r"\b(wp_verify_nonce|check_ajax_referer|check_admin_referer)\s*\(",
            scope_text,
        )
    )


# ── Constant-source URL detection ───────────────────────────────────────────

_CONST_URL_PATTERNS = re.compile(
    r"""
    (?:
      ['"]https?://[^'"]{4,}['"]     # a hardcoded URL string literal
    | plugin_dir_url\s*\(            # WordPress plugin-URL helper
    | plugins_url\s*\(
    | home_url\s*\(
    | site_url\s*\(
    | admin_url\s*\(
    | get_option\s*\(                # an option value — not user-controlled in the normal case
    | get_transient\s*\(
    | \$this\s*->\s*\w+_url\b        # $this->base_url, $this->api_url, etc.
    | \$this\s*->\s*endpoint\b
    )
    """,
    re.VERBOSE | re.I,
)


def url_is_constant_source(url_expr: str) -> bool:
    """True if the URL expression originates from a constant/configured source."""
    return bool(_CONST_URL_PATTERNS.search(url_expr))


# ── Scope-local taint check ──────────────────────────────────────────────────


# ── String-literal detection ───────────────────────────────────────────────


def is_inside_string_literal(line: str, pos: int) -> bool:
    """
    Return True if the character offset `pos` in `line` falls inside a
    single- or double-quoted PHP string literal.

    This closes a real false-positive class found while scanning
    woocommerce-gateway-stripe: a
    regex like `\\bsystem\\s*\\(` matches the substring "system (" inside
    the plain string literal 'Size system (ISO 3166 country code)' -- there
    is no function call on that line at all, just a word that happens to
    look like one. The same class of bug affects secret-pattern matching:
    `sk_live_` can appear inside a UI description string ("...starting
    with \"sk_live_\"...") or a PHPDoc example, neither of which is an
    actual credential.

    The scan is a simple linear walk tracking quote state and backslash
    escapes. It does not need to be a full PHP tokenizer: false negatives
    (failing to detect a string) only make the caller slightly more
    cautious, and false positives (wrongly treating code as a string) are
    rare in practice for the single-line context these rules operate on.

    Example:
        line = "'description' => 'Size system (ISO code)',"
        is_inside_string_literal(line, line.index("system"))  -> True

        line = "system($_GET['cmd']);"
        is_inside_string_literal(line, line.index("system"))  -> False
    """
    in_single = False
    in_double = False
    i = 0
    while i < pos and i < len(line):
        ch = line[i]
        if ch == "\\" and (in_single or in_double):
            i += 2  # skip the escaped character entirely
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        i += 1
    return in_single or in_double


def var_tainted_in_scope(var_name: str, scope_text: str) -> bool:
    """
    A lightweight, scope-local taint check: True if $var_name is assigned
    from $_GET/$_POST/$_REQUEST/$_COOKIE anywhere in scope_text.

    This complements the full dataflow.analyze() engine for callers that
    only need a quick yes/no answer within a known text window.
    """
    return bool(
        re.search(
            r"\$" + re.escape(var_name) + r"\s*=.*\$_(GET|POST|REQUEST|COOKIE)",
            scope_text,
        )
    )
