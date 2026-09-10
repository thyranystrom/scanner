r"""
dangerous_functions.py
----------------------
Flags dangerous PHP functions EXCEPT unserialize(), which is handled
exclusively by owasp_top10.py (WC-OWASP-008, CRITICAL) to avoid duplicate
findings with different severity levels for the same call.

String-literal awareness
----------------------------------
Fixes a real false positive found while scanning
woocommerce-gateway-stripe: the pattern `\bsystem\s*\(` matched the substring
"system (" inside the plain PHP string literal
'Size system (ISO 3166 country code)' -- there was no function call
anywhere on that line, just a word that happens to look like one followed
by a parenthesis a few characters later.

The existing comment-line guard doesn't help here because this is not a
comment line, it's a normal array literal. fp_reducer.is_inside_string_literal()
closes the gap by tracking quote state across the line and rejecting any
match that falls inside quotes.
"""

import re

from ..fp_reducer import is_inside_string_literal, phpcs_suppresses
from ..models import Finding
from ..utils import line_number, snippet

# unserialize is excluded here — handled by owasp_top10 (CRITICAL)
FUNCTIONS = ("eval", "exec", "shell_exec", "system", "passthru")
PATTERN = re.compile(r"\b(" + "|".join(map(re.escape, FUNCTIONS)) + r")\s*\(")


def scan_dangerous(path, text, project=None):
    findings = []
    lines = text.splitlines()

    for m in PATTERN.finditer(text):
        fn = m.group(1)
        line = line_number(text, m.start())
        raw = lines[line - 1] if line <= len(lines) else ""

        # Guard 1: skip comment lines entirely — a doc-block explaining
        # "don't use eval()" should not itself trigger the rule.
        stripped = raw.lstrip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue

        # Guard 2: skip matches inside string literals (the system() bug
        # described in the module docstring above). Convert the match's
        # absolute offset in `text` to a column within its own line, then
        # ask fp_reducer whether that column sits inside quotes.
        line_start_offset = text.rfind("\n", 0, m.start()) + 1
        col_in_line = m.start() - line_start_offset
        if is_inside_string_literal(raw, col_in_line):
            continue

        # Guard 3: an explicit phpcs:ignore is the developer's informed call.
        if phpcs_suppresses(lines, line):
            continue

        findings.append(
            Finding(
                rule_id="WC-DANGER-001",
                severity="HIGH",  # these functions are always high-risk when real
                title=f"Use of dangerous function: {fn}",
                file=str(path),
                line=line,
                message=(
                    f"{fn}() can execute arbitrary code. "
                    "Verify no attacker-controlled data reaches this call. "
                    "If intentional, add a phpcs:ignore comment explaining why."
                ),
                owasp="A05:2025-Injection",
                confidence=0.75,
                evidence=snippet(lines, line),
                source="user input (unverified)",
                sink=f"{fn}()",
            )
        )

    return findings
