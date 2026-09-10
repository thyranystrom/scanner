"""
secrets.py
----------
FIX: The regex used to match comment lines -- '// api_key: "example"' would
     trigger a HIGH finding. Comment lines (//, #, *, /* ... */) are now
     filtered out BEFORE matching. Inline comments on code lines are
     handled too. Placeholder/example values automatically lower
     confidence. Confidence is computed via confidence.score_secret().
"""

from __future__ import annotations

import re

from ..confidence import score_secret
from ..models import Finding
from ..utils import line_number, snippet

# Main pattern: keyname = 'value' (>= 12 characters)
SECRET = re.compile(
    r"("
    r"api[_-]?key|secret|password|private[_-]?key|access[_-]?token|"
    r"klarna[_-]?(?:secret|key|token)|svea[_-]?(?:secret|key)|"
    r"walley[_-]?(?:secret|key)|billie[_-]?(?:secret|key)|"
    r"stripe[_-]?(?:secret|key)|merchant[_-]?(?:key|secret)|"
    r"sk_live_[0-9a-zA-Z]{24}|sk_test_[0-9a-zA-Z]{24}|"
    r"bearer\s+[A-Za-z0-9\-\._~\+\/]{20,}"
    r")"
    r"\s*[:=]\s*['\"][^'\"]{12,}['\"]",
    re.I,
)

# Live-credential formats significantly boost confidence
_LIVE_CRED = re.compile(r"sk_live_|rk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}", re.I)

# Placeholder-looking values lower confidence
_PLACEHOLDER = re.compile(
    r"(example|placeholder|your[_-]?(?:key|secret|token)|change[_-]?me|"
    r"insert[_-]?here|test[_-]?(?:key|secret)|dummy|xxx+|sample|replace|"
    r"xxxxxxxx|put[_-]?your|masked|empty_secret|empty_headers|empty_body)",
    re.I,
)
_STATUS_CONST = re.compile(r"(VALIDATION_|ERROR_|STATUS_|FAILED_|MASKED_|EMPTY_SECRET)", re.I)

# Comment detection
_FULL_COMMENT = re.compile(r"^\s*(?://|#|\*|/\*)")
_PHPCS = re.compile(r"phpcs\s*:\s*ignore", re.I)


def _strip_inline_comment(raw: str) -> str:
    """
    Strip everything from // or # onward, while respecting string literals.
    A simple character walk -- does not handle escaped quotes, but covers
    the overwhelming majority of real-world PHP source lines.
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(raw):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double and (raw[i : i + 2] in ("//", "/*") or ch == "#"):
            return raw[:i]
    return raw


def _build_clean_text(lines: list[str]) -> str:
    """
    Return the text with comment blocks/lines replaced by blank lines
    (line numbers are preserved for the later line_number() lookup).
    """
    out = []
    in_block = False
    for raw in lines:
        if in_block:
            out.append("")
            if "*/" in raw:
                in_block = False
            continue
        if "/*" in raw and not _FULL_COMMENT.match(raw):
            # A block comment starts WITH code on the same line -- keep the code part.
            pre = raw[: raw.index("/*")]
            out.append(_strip_inline_comment(pre))
            if "*/" not in raw[raw.index("/*") :]:
                in_block = True
            continue
        if _FULL_COMMENT.match(raw):
            out.append("")
            if "/*" in raw and "*/" not in raw:
                in_block = True
            continue
        out.append(_strip_inline_comment(raw))
    return "\n".join(out)


def scan_secrets(path, text, project=None):
    findings = []
    lines = text.splitlines()
    clean = _build_clean_text(lines)

    for m in SECRET.finditer(clean):
        line_no = line_number(clean, m.start())
        raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
        matched = m.group(0)
        label = m.group(1)

        phpcs_suppress = bool(_PHPCS.search(raw_line)) or (
            line_no >= 2 and bool(_PHPCS.search(lines[line_no - 2]))
        )
        is_live = bool(_LIVE_CRED.search(matched))
        is_placeholder = bool(_PLACEHOLDER.search(matched))
        if _STATUS_CONST.search(raw_line) or re.search(r"\bMASKED_|\bVALIDATION_FAILED_", raw_line):
            continue
        if re.search(r"\*{3,}", matched):
            continue
        # "Hardcoded" means not sourced from getenv/get_option/define/a constant.
        is_hardcoded = not bool(
            re.search(r"getenv\s*\(|get_option\s*\(|define\s*\(|\$_ENV|\$_SERVER", raw_line)
        )

        conf = score_secret(
            live_credential=is_live,
            hardcoded=is_hardcoded,
            in_comment=False,  # comments were already filtered out above
            phpcs_suppress=phpcs_suppress,
            placeholder=is_placeholder,
        )

        sev = "HIGH" if conf >= 0.68 else ("MEDIUM" if conf >= 0.44 else "LOW")

        findings.append(
            Finding(
                rule_id="WC-SECRET-001",
                severity=sev,
                title=(
                    "Possible hard-coded secret"
                    + (" (live credential)" if is_live else "")
                    + (" -- likely placeholder" if is_placeholder else "")
                ),
                file=str(path),
                line=line_no,
                message=(
                    "Review manually. If this is a real credential, rotate it and "
                    "store it in environment variables or wp_options (encrypted)."
                    + (
                        " Placeholder value detected -- probably low risk."
                        if is_placeholder
                        else ""
                    )
                    + (" PHPCS suppression on line." if phpcs_suppress else "")
                ),
                owasp="A04:2025-Cryptographic Failures",
                confidence=conf,
                evidence=snippet(lines, line_no),
                source=label,
                sink="hard-coded string literal",
            )
        )

    return findings
