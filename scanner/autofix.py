"""
autofix.py
----------
Automated code-change suggestions, one per Finding.

Architecture
------------
  CodeFix      – a concrete suggestion: original line, new line, diff, confidence
  FixStrategy  – base class; each rule ID has a concrete subclass
  FixEngine    – generates a CodeFix list for a list of findings + PHP source code
  apply_fixes  – applies confirmed fixes to a source-code string (safe, in-place)

Rules covered
----------------
  WC-INPUT-001/002/003  ->  sanitize_text_field() / absint() / sanitize_email()
  WC-SQL-001            ->  $wpdb->prepare() with the correct placeholder (%s / %d)
  WC-XSS-001            ->  esc_html() around the variable in output context
  WC-OUTPUT-001         ->  esc_html() in echo / print
  WC-SECRET-001         ->  get_option() replacing the hardcoded value
  WC-AUTH-001           ->  check_ajax_referer() in the AJAX handler
  WC-OWASP-002          ->  md5/sha1 -> wp_hash_password / hash('sha256')
  WC-OWASP-008          ->  unserialize() -> json_decode()
  WC-DANGER-001         ->  security-review comment + warning (cannot be auto-replaced)

Confidence
----------
  >= 0.90  ->  auto_apply=True  (safe to apply directly via --fix-apply)
  <  0.90  ->  auto_apply=False (review the diff manually before applying)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# CodeFix -- public data type
# ---------------------------------------------------------------------------


@dataclass
class CodeFix:
    rule_id: str
    file: str
    line: int  # 1-based line number
    original_line: str  # the exact original line (no trailing newline)
    fixed_line: str  # the suggested replacement
    description: str
    confidence: float  # 0.0–1.0
    diff: str = ""  # unified diff-snippet (auto-genereras)
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.diff:
            self.diff = (
                f"--- {self.file}:{self.line}\n"
                f"+++ {self.file}:{self.line}\n"
                f"-{self.original_line}\n"
                f"+{self.fixed_line}"
            )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "original": self.original_line,
            "fixed": self.fixed_line,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "diff": self.diff,
            "references": self.references,
            "auto_apply": self.confidence >= 0.90,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _already_wrapped(line: str, expr: str, fn: str) -> bool:
    return bool(re.search(re.escape(fn) + r"\s*\(\s*" + re.escape(expr), line))


def _make_fix(
    finding, orig: str, fixed: str, desc: str, conf: float, refs: list[str] | None = None
) -> CodeFix:
    return CodeFix(
        rule_id=finding.rule_id,
        file=str(finding.file),
        line=finding.line,
        original_line=orig,
        fixed_line=fixed,
        description=desc,
        confidence=conf,
        references=refs or [],
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


class _InputFix:
    """WC-INPUT-001/002/003 -- picks the right sanitizer based on the key name."""

    _NUMERIC = re.compile(
        r"\b(id|qty|quantity|page|offset|limit|count|num|price|amount|order_id)\b", re.I
    )
    _EMAIL = re.compile(r"\b(email|mail)\b", re.I)
    _SUPERG = re.compile(r"(\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"](\w+)['\"]\s*\])")

    def generate(self, finding, line: str) -> list[CodeFix]:
        m = self._SUPERG.search(line)
        if not m:
            return []
        expr, _sg, key = m.group(1), m.group(2), m.group(3)

        if self._NUMERIC.search(key):
            fn, conf = "absint", 0.93
        elif self._EMAIL.search(key):
            fn, conf = "sanitize_email", 0.91
        else:
            fn, conf = "sanitize_text_field", 0.89

        if _already_wrapped(line, expr, fn):
            return []

        fixed = line.replace(expr, f"{fn}( {expr} )", 1)
        return [
            _make_fix(
                finding,
                line,
                fixed,
                f"Wrap {expr} with {fn}() to sanitize '{key}' before use.",
                conf,
                ["https://developer.wordpress.org/apis/security/sanitizing/"],
            )
        ]


class _SqlFix:
    """WC-SQL-001 -- converts interpolated queries into $wpdb->prepare().

    FIX: the variable-extraction regex used to match $wpdb itself whenever
    it appeared as {$wpdb->prefix} (the standard WordPress table-prefix
    pattern found in virtually every real query). Because \\w* stops at the
    "->" operator, only the "{$wpdb" portion got replaced with a
    placeholder, leaving the dangling "->prefix}" behind and producing
    invalid PHP such as:

        "SELECT * FROM %s->prefix}posts WHERE id = %d"

    $wpdb was also then incorrectly passed as a bind argument to
    prepare(), which is nonsensical -- $wpdb is the database object, not a
    tainted value to parameterize. The fix below excludes any variable
    immediately followed by "->" (an object-property/method access) from
    the set of candidates, so {$wpdb->prefix} is left untouched as literal
    query text (a table/column name; prepare() cannot parameterize
    identifiers anyway) while genuinely tainted values like {$id} or
    {$status} are still correctly replaced with %s/%d.

    A second, narrower fix: when a matched variable sits directly between
    literal '%' characters (a SQL LIKE wildcard pattern, e.g. '%{$term}%'),
    a naive %s substitution produces a string that $wpdb->prepare()'s own
    escaping rules would misinterpret (bare '%' characters outside of a
    recognized placeholder are treated specially by prepare()). Rather than
    emit a subtly-broken fix for that case, this strategy declines to
    auto-generate a suggestion and leaves it for manual review instead.
    """

    # Matches $wpdb->method("... $var ...") as a statement
    _CALL = re.compile(
        r"(\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col))"
        r"\s*\(\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')\s*\)"
    )

    # A bare variable reference (no brace-consumption here -- see generate()
    # for why detection and substitution are handled as separate passes).
    _VAR = re.compile(r"\$([A-Za-z_]\w*)")

    def generate(self, finding, line: str) -> list[CodeFix]:
        m = self._CALL.search(line)
        if not m:
            return []
        method = m.group(1)
        raw = m.group(2)
        inner = raw[1:-1]  # strip quotes

        # Detection pass: find every $variable, then exclude any immediately
        # followed by "->" (object property/method access). This is done as
        # a post-match check on plain text rather than a regex lookahead,
        # because a lookahead combined with a greedy \w* is prone to
        # backtracking: matching $wpdb with (?!\s*->) fails, so the engine
        # backtracks to the shorter $wpd, which IS followed by "b" (not
        # "->") and wrongly succeeds -- producing corrupted output like
        # "%sb->prefix}" instead of leaving "{$wpdb->prefix}" untouched.
        vars_: list[str] = []
        for vm in self._VAR.finditer(inner):
            name = vm.group(1)
            if inner[vm.end() : vm.end() + 2] == "->":
                continue  # object access, e.g. $wpdb->prefix -- not a bind value
            if name not in vars_:
                vars_.append(name)
        if not vars_:
            return []

        # Bail out on SQL LIKE wildcard patterns ('%{$var}%') -- see the
        # class docstring for why a naive %s substitution is unsafe here.
        for v in vars_:
            wildcard = re.search(r"%\s*\{?\$" + re.escape(v) + r"\}?\s*%", inner)
            if wildcard:
                return []

        clean = inner
        for v in vars_:
            ph = "%d" if re.search(r"(?:id|qty|num|page|count)$", v, re.I) else "%s"
            # (?!\w) prevents "$status" from matching inside "$status_extra".
            clean = re.sub(
                r"\{?\$" + re.escape(v) + r"(?!\w)\}?",
                ph,
                clean,
                count=1,
            )

        args = ", ".join(f"${v}" for v in vars_)
        fixed = line.replace(
            m.group(0),
            f'{method}( $wpdb->prepare( "{clean}", {args} ) )',
            1,
        )
        return [
            _make_fix(
                finding,
                line,
                fixed,
                "Replace interpolated SQL with $wpdb->prepare(). "
                "Verify placeholder types (%s/%d) match actual data types.",
                0.82,  # < 0.90: requires review of the placeholder type
                ["https://developer.wordpress.org/reference/classes/wpdb/prepare/"],
            )
        ]


class _OutputFix:
    """WC-OUTPUT-001 / WC-XSS-001 -- adds esc_html() to echo/print."""

    _ECHO_VAR = re.compile(r"\becho\s+(\$[A-Za-z_]\w*)\s*;")
    _ECHO_CONCAT = re.compile(r"\becho\s+(.+?)\s*;$")
    _PRINT_VAR = re.compile(r"\bprint\s*\(\s*(\$[A-Za-z_]\w*)\s*\)\s*;")
    _ECHO_INTERP = re.compile(r'\becho\s+"([^"]*\$[A-Za-z_]\w*[^"]*)"\s*;')

    def generate(self, finding, line: str) -> list[CodeFix]:
        # echo $var;
        m = self._ECHO_VAR.search(line)
        if m:
            var = m.group(1)
            if _already_wrapped(line, var, "esc_html"):
                return []
            fixed = line.replace(f"echo {var};", f"echo esc_html( {var} );", 1)
            return [
                _make_fix(
                    finding,
                    line,
                    fixed,
                    f"Wrap {var} with esc_html() to prevent XSS.",
                    0.93,
                    ["https://developer.wordpress.org/reference/functions/esc_html/"],
                )
            ]

        # print($var);
        m = self._PRINT_VAR.search(line)
        if m:
            var = m.group(1)
            fixed = line.replace(m.group(0), f"echo esc_html( {var} );", 1)
            return [
                _make_fix(
                    finding,
                    line,
                    fixed,
                    f"Replace print({var}) with echo esc_html({var}).",
                    0.90,
                    ["https://developer.wordpress.org/reference/functions/esc_html/"],
                )
            ]

        # echo "string $var string";  ->  break into esc_html()-wrapped concatenation
        m = self._ECHO_INTERP.search(line)
        if m:
            inner = m.group(1)
            parts, last = [], 0
            for vm in re.finditer(r"\$([A-Za-z_]\w*)", inner):
                if last < vm.start():
                    parts.append(f'"{inner[last : vm.start()]}"')
                parts.append(f"esc_html( ${vm.group(1)} )")
                last = vm.end()
            if last < len(inner):
                parts.append(f'"{inner[last:]}"')
            fixed = _indent(line) + "echo " + " . ".join(parts) + ";"
            return [
                _make_fix(
                    finding,
                    line,
                    fixed,
                    "Break interpolated string into esc_html() calls per variable.",
                    0.78,
                    ["https://developer.wordpress.org/reference/functions/esc_html/"],
                )
            ]

        return []


class _SecretFix:
    """WC-SECRET-001 -- replace a hardcoded value with get_option()."""

    _ASSIGN = re.compile(r"(\$\w+)\s*=\s*['\"]([^'\"]{12,})['\"]")

    def generate(self, finding, line: str) -> list[CodeFix]:
        m = self._ASSIGN.search(line)
        if not m:
            return []
        var = m.group(1)
        key = "wc_" + re.sub(r"[^a-z0-9_]", "_", var.lstrip("$").lower())
        fixed = line.replace(m.group(0), f"{var} = get_option( '{key}', '' )", 1)
        return [
            _make_fix(
                finding,
                line,
                fixed,
                f"Replace hard-coded credential with get_option('{key}'). "
                "Add a settings field and rotate the exposed secret.",
                0.74,
                ["https://developer.wordpress.org/reference/functions/get_option/"],
            )
        ]


class _WeakCryptoFix:
    """WC-OWASP-004 -- md5/sha1 -> wp_hash_password or hash('sha256')."""

    def generate(self, finding, line: str) -> list[CodeFix]:
        fixes = []
        for fn in ("md5", "sha1"):
            m = re.search(rf"\b{fn}\s*\(([^)]+)\)", line)
            if not m:
                continue
            arg = m.group(1).strip()
            if re.search(r"pass(word)?|pwd", line, re.I):
                repl, desc, conf = (
                    f"wp_hash_password( {arg} )",
                    f"Replace {fn}() with wp_hash_password() for password storage.",
                    0.88,
                )
            else:
                repl, desc, conf = (
                    f"hash( 'sha256', {arg} )",
                    f"Replace {fn}() with hash('sha256', ...) for integrity checks.",
                    0.86,
                )
            fixed = line.replace(m.group(0), repl, 1)
            fixes.append(
                _make_fix(
                    finding,
                    line,
                    fixed,
                    desc,
                    conf,
                    ["https://developer.wordpress.org/reference/functions/wp_hash_password/"],
                )
            )
        return fixes


class _UnserializeFix:
    """WC-OWASP-008 -- unserialize() -> json_decode()."""

    def generate(self, finding, line: str) -> list[CodeFix]:
        m = re.search(r"unserialize\s*\(([^)]+)\)", line)
        if not m:
            return []
        arg = m.group(1).strip()
        fixed = line.replace(m.group(0), f"json_decode( {arg}, true )", 1)
        return [
            _make_fix(
                finding,
                line,
                fixed,
                "Replace unserialize() with json_decode(). "
                "If data is PHP-serialized, migrate storage format first.",
                0.80,
                ["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
            )
        ]


# Pattern for pre-auth handlers: sign-in, redirect, callback, OAuth, etc.
# These cannot require a WP nonce -- the user is not logged in yet.
_PRE_AUTH_HANDLER = re.compile(
    r"(sign[_-]?in|log[_-]?in|callback|redirect|oauth|token|jwt|sso|"
    r"auth[_-]?redirect|from[_-]?redirect|verify[_-]?token)",
    re.I,
)


class _AuthFix:
    """
    WC-AUTH-001 -- suggests check_ajax_referer() for AJAX handlers.

    Exception: handlers whose action name or title matches a pre-auth
    pattern (sign_in, redirect, callback, oauth, etc.) cannot require a
    WP nonce -- the user is not logged in yet. For these, a security-
    review comment is returned instead.
    """

    _FUNC_OPEN = re.compile(r"(function\s+\w+\s*\([^)]*\)\s*\{)")

    def generate(self, finding, line: str) -> list[CodeFix]:
        # Extract action/title from the finding to determine the handler type
        title = str(
            getattr(finding, "title", None) or finding.get("title", "")
            if hasattr(finding, "get")
            else getattr(finding, "title", "")
        )
        source = str(
            getattr(finding, "source", None) or finding.get("source", "")
            if hasattr(finding, "get")
            else getattr(finding, "source", "")
        )
        context = (title + " " + source + " " + line).lower()

        # Pre-auth handler: a nonce check is the wrong fix here; give a review comment instead
        if _PRE_AUTH_HANDLER.search(context):
            ind = _indent(line)
            lines_c = [
                "// SECURITY REVIEW: Pre-auth handler (sign-in/redirect/callback).",
                "// WP nonce cannot be used here – user is not yet logged in.",
                "// Verify that JWT/token validation runs before any sensitive operation,",
                "// and that signatures are checked with RS256/HS256 against a JWKS endpoint.",
            ]
            comment = "".join(ind + line_c + "\n" for line_c in lines_c)
            fixed = comment + line
            return [
                _make_fix(
                    finding,
                    line,
                    fixed,
                    "Pre-auth handler detected – WP nonce cannot be used. "
                    "Review JWT/token validation instead.",
                    0.55,
                    ["https://developer.wordpress.org/reference/functions/check_ajax_referer/"],
                )
            ]

        # Standard AJAX handler: suggest check_ajax_referer()
        m = self._FUNC_OPEN.search(line)
        ind = _indent(line) + "    "
        nonce_line = "\n" + ind + "check_ajax_referer( 'YOUR_ACTION_NONCE', '_wpnonce' );"

        if m:
            fixed = line.replace(m.group(0), m.group(0) + nonce_line, 1)
            conf = 0.72
            desc = "Add check_ajax_referer() at top of AJAX handler. Replace 'YOUR_ACTION_NONCE'."
        else:
            fixed = line + nonce_line
            conf = 0.60
            desc = (
                "Add check_ajax_referer() call. Replace 'YOUR_ACTION_NONCE' with your nonce action."
            )

        return [
            _make_fix(
                finding,
                line,
                fixed,
                desc,
                conf,
                ["https://developer.wordpress.org/reference/functions/check_ajax_referer/"],
            )
        ]


class _DangerousFix:
    """WC-DANGER-001 -- eval/exec etc. -- add a security-review comment."""

    def generate(self, finding, line: str) -> list[CodeFix]:
        m = re.search(r"\b(eval|exec|shell_exec|system|passthru)\b", line)
        if not m:
            return []
        fn = m.group(1)
        ind = _indent(line)
        fixed = f"{ind}// SECURITY REVIEW REQUIRED: {fn}() detected – remove or replace.\n{line}"
        return [
            _make_fix(
                finding,
                line,
                fixed,
                f"{fn}() cannot be safely auto-replaced. Security comment added; manual review required.",
                0.55,
            )
        ]


# ---------------------------------------------------------------------------
# Strategi-register
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, list] = {
    "WC-INPUT-001": [_InputFix()],
    "WC-INPUT-002": [_InputFix()],
    "WC-INPUT-003": [_InputFix()],
    "WC-SQL-001": [_SqlFix()],
    "WC-XSS-001": [_OutputFix()],
    "WC-OUTPUT-001": [_OutputFix()],
    "WC-SECRET-001": [_SecretFix()],
    "WC-AUTH-001": [_AuthFix()],
    "WC-OWASP-004": [_WeakCryptoFix()],
    "WC-OWASP-008": [_UnserializeFix()],
    "WC-DANGER-001": [_DangerousFix()],
}


# ---------------------------------------------------------------------------
# FixEngine -- public entry point
# ---------------------------------------------------------------------------


class FixEngine:
    """
    Generates CodeFix objects for a list of Findings against a PHP source string.

    Exempel:
        engine = FixEngine()
        fixes  = engine.suggest(findings, php_source_code)
    """

    def suggest(self, findings: list, source_code: str) -> list[CodeFix]:
        lines = source_code.splitlines()
        result: list[CodeFix] = []
        used: set[int] = set()  # en fix per radnummer

        for finding in findings:
            rule_id = getattr(finding, "rule_id", None) or finding.get("rule_id", "")
            line_no = int(getattr(finding, "line", 0) or finding.get("line", 0))

            if not rule_id or line_no < 1 or line_no > len(lines):
                continue
            if line_no in used:
                continue

            source_line = lines[line_no - 1]
            strategies = _REGISTRY.get(rule_id, [])

            for strategy in strategies:
                fixes = strategy.generate(finding, source_line)
                if fixes:
                    result.extend(fixes)
                    used.add(line_no)
                    break

        return result

    def suggest_for_file(self, findings: list, file_path: str) -> list[CodeFix]:
        """Convenience method: read the file from disk, return suggestions for it."""
        from pathlib import Path

        text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        relevant = [
            f for f in findings if str(getattr(f, "file", None) or f.get("file", "")) == file_path
        ]
        return self.suggest(relevant, text)


# ---------------------------------------------------------------------------
# apply_fixes -- applies fixes to a source-code string
# ---------------------------------------------------------------------------


def apply_fixes(source_code: str, fixes: list[CodeFix]) -> str:
    """
    Applies a list of CodeFix objects to the source-code string.
    - Sorts bottom-to-top (preserves line numbers for earlier fixes).
    - Verifies the original line still matches before writing.
    - Overlapping fixes (same line): the first one wins.
    Returns the modified source code.
    """
    lines = source_code.splitlines(keepends=True)
    applied: set[int] = set()

    for fix in sorted(fixes, key=lambda f: f.line, reverse=True):
        idx = fix.line - 1
        if idx < 0 or idx >= len(lines) or fix.line in applied:
            continue
        current = lines[idx].rstrip("\r\n")
        if current != fix.original_line:
            continue  # the line content has changed -- skip it
        eol = "\n"
        lines[idx] = fix.fixed_line + eol
        applied.add(fix.line)

    return "".join(lines)
