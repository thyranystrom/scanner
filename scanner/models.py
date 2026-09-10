"""
models.py
---------
Core data model for the security scanner.

Finding is the single output type produced by every rule module. It is
frozen (immutable) so it can be safely shared across threads during the
parallel file-scanning pass in main.py.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass

_KNOWN_CREDENTIAL_FORMATS = [
    (r"sk_live_[A-Za-z0-9]+", "sk_live_[REDACTED]"),
    (r"sk_test_[A-Za-z0-9]+", "sk_test_[REDACTED]"),
    (r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]"),
    (r"ghp_[A-Za-z0-9]{36}", "ghp_[REDACTED]"),
]

# Generic fallback: redact the VALUE half of any "sensitive-looking-name =
# 'value'" assignment, regardless of format. The four patterns above only
# recognize specific, well-known credential shapes (Stripe, AWS, GitHub);
# a plain database password, a custom API key format, or any other secret
# that WC-SECRET-001's broader detection catches would otherwise appear in
# FULL PLAINTEXT in generated JSON/Markdown reports. This is a real gap
# found by testing the scanner against its own worst-case input: a
# database password like "MyRealProductionDbPassword2024!" reached this
# function completely unredacted before this fallback was added.
_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"((?:password|passwd|pwd|secret|api[_-]?key|apikey|token|credential)\w*"
    r"\s*[:=]>?\s*)"
    r"['\"]([^'\"]{4,})['\"]",
    re.I,
)


def redact_secrets(text: str) -> str:
    """
    Replace recognizable secret values in a string with a redacted
    placeholder before it is written to any report.

    This matters because a Finding's `evidence` and `message` fields often
    contain the exact source line that triggered the finding — which, for
    WC-SECRET-001/002 findings, is precisely a line that may contain a real
    leaked key. Scanning for secrets should not itself become a second way
    to leak them into a CI log or a shared report file.

    Two layers, applied in order:
      1. Known credential formats (Stripe, AWS, GitHub) -- matched anywhere
         in the text, independent of surrounding syntax, so a prefix like
         "sk_live_" can still be shown for readability while the sensitive
         suffix is redacted.
      2. A generic "sensitive-name = 'value'" fallback that redacts the
         entire value for anything not already caught above -- this is
         what protects arbitrary-format secrets (plain passwords, custom
         API key shapes) that the specific patterns don't recognize.

    The generic pass skips any value that already contains "REDACTED"
    (case-insensitive) so it doesn't clobber layer 1's more informative
    "sk_live_[REDACTED]" output back down to a bare "[REDACTED]".
    """
    if not text:
        return text
    for pat, repl in _KNOWN_CREDENTIAL_FORMATS:
        text = re.sub(pat, repl, text)

    def _redact_generic(m: re.Match[str]) -> str:
        if "redacted" in m.group(2).lower():
            return m.group(0)  # already redacted by layer 1 -- leave as-is
        return f"{m.group(1)}'[REDACTED]'"

    return _GENERIC_SECRET_ASSIGNMENT.sub(_redact_generic, text)


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by one rule module."""

    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    message: str
    owasp: str
    confidence: float
    evidence: str | None = None
    source: str | None = None
    sink: str | None = None
    flow_type: str | None = None
    taint_line: int | None = None

    def fingerprint(self) -> str:
        """
        Compute a stable identifier used for baseline matching and for
        deduplicating findings that different rules raised on the same
        underlying issue.

        Includes:
          - rule_id, the normalized file path, source, sink, and title
          - a hash of the actual flagged source line (from the evidence
            snippet), when available

        The source-line hash is what makes baselines resilient to
        unrelated edits: if a developer adds a comment above the flagged
        code, shifting its line number, the fingerprint stays the same and
        the baseline entry still matches. But if the flagged line itself
        is rewritten, the fingerprint correctly changes too. This is more
        robust than relying on the line number alone, as an earlier
        version of this method did.
        """
        file_norm = str(self.file).replace("\\", "/").lower()

        # Pull the specific flagged line out of the evidence snippet (the
        # line marked with a ◀ arrow in the terminal output), if present;
        # otherwise fall back to an empty string, making the fingerprint
        # independent of the line number in that case.
        code_node = ""
        if self.evidence:
            for ev_line in self.evidence.splitlines():
                # Evidence lines are formatted with a line number prefix: "  42: <code>"
                import re as _re

                m = _re.match(r"\s*(\d+):\s?(.*)", ev_line)
                if m and int(m.group(1)) == (self.line or 0):
                    code_node = _re.sub(r"\s+", " ", m.group(2).strip()).lower()
                    break

        raw = "|".join(
            [
                self.rule_id,
                file_norm,
                (self.source or "")[:120].lower(),
                (self.sink or "")[:120].lower(),
                re.sub(r"\s+", " ", (self.title or "").strip().lower())[:160],
                code_node[:200],  # hash of the code node itself — a line shift doesn't affect this
            ]
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self):
        """Convert to a plain dict for JSON/Markdown report generation, with secrets redacted."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        if d.get("evidence"):
            d["evidence"] = redact_secrets(d["evidence"])
        if d.get("message"):
            d["message"] = redact_secrets(d["message"])
        return d
