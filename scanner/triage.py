"""
triage.py
---------
Triage helpers for manual review and automatic false-positive classification.

Provides:
  - AutoClassifier: classifies findings as likely true positive, likely
    false positive, or "needs review" based on confidence, contextual
    signals, and patterns.
  - Exports the triage queue as a Markdown checklist or as JSON.
  - fp_reducer integration: shares classification signals with fp_reducer.py.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .models import Finding

PRIORITY = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# Core triage functions
# ---------------------------------------------------------------------------


def split_by_severity(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = {s: [] for s in PRIORITY}
    for f in findings:
        buckets.setdefault(f.severity, []).append(f)
    return buckets


def manual_review_queue(
    findings: Sequence[Finding],
    *,
    min_severity: str = "HIGH",
) -> list[Finding]:
    thr = PRIORITY.index(min_severity) if min_severity in PRIORITY else 1
    return [f for f in findings if PRIORITY.index(f.severity) <= thr]


def triage_lines(findings: Sequence[Finding]) -> list[str]:
    """Plain-text checklist suitable for copy/paste into a ticket."""
    queue = manual_review_queue(findings, min_severity="HIGH")
    if not queue:
        return [
            "No HIGH/CRITICAL findings.",
            "Optional: skim MEDIUM if you have time; LOWs are noise/review hints.",
        ]
    lines = [
        f"Manual review queue: {len(queue)} finding(s) (HIGH/CRITICAL)",
        "For each item: open the file:line -> confirm exploitability -> mark TP / FP / Accept.",
        "",
    ]
    for i, f in enumerate(queue, 1):
        loc = f"{f.file}:{f.line}".replace("\\", "/")
        verdict = AutoClassifier.classify(f)
        verdict_tag = f"  [{verdict.label}]" if verdict.label != "review" else ""
        lines.append(f"{i}. [{f.severity}] {f.rule_id}  conf={f.confidence:.0%}{verdict_tag}")
        lines.append(f"   {loc}")
        lines.append(f"   {f.title}")
        if f.source or f.sink:
            lines.append(f"   flow: {f.source or '?'} -> {f.sink or '?'}")
        if verdict.reason:
            lines.append(f"   auto: {verdict.reason}")
        lines.append("   action: [ ] TP  [ ] FP  [ ] Accept into baseline")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# AutoClassifier -- automatic FP/TP classification
# ---------------------------------------------------------------------------


@dataclass
class Verdict:
    """
    The result of automatic classification.

    label:  "likely_tp"  -- high probability this is a genuine vulnerability
            "likely_fp"  -- high probability this is a false alarm
            "review"     -- manual review is required
    confidence: 0.0-1.0  (the classifier's own confidence, distinct from the
                          finding's own confidence score)
    reason: A short explanation for the classification.
    """

    label: str
    confidence: float
    reason: str = ""


class AutoClassifier:
    """
    Classifies a Finding as likely a true positive, likely a false
    positive, or needing manual review, based on a small set of signal
    rules evaluated in priority order.

    Used by triage_lines() and can also be called directly in tests.
    """

    # Patterns suggesting test/vendor code (lower real-world risk)
    _TEST_PATH = re.compile(
        r"(test|spec|fixture|vendor|node_modules|\.git|mock|stub|fake|dummy)",
        re.I,
    )

    # Patterns suggesting a genuine, exploitable sink in production code
    _PROD_SINK = re.compile(
        r"\b(query|get_results|get_row|wp_remote_get|wp_remote_post|"
        r"shell_exec|eval|exec|unserialize)\b",
        re.I,
    )

    # Patterns suggesting the code already has protection in place
    _PROTECTION = re.compile(
        r"\b(prepare|esc_html|esc_attr|sanitize_text_field|absint|"
        r"wp_verify_nonce|check_ajax_referer|current_user_can)\b",
        re.I,
    )

    @classmethod
    def classify(cls, f: Finding) -> Verdict:
        """
        Classify a Finding and return a Verdict.

        Signal rules, evaluated in this order (first match wins):
          1. Confidence < 0.20            -> likely_fp (the scanner itself is unsure)
          2. Proven taint chain + sensitive sink -> likely_tp
          3. Test/vendor file path         -> likely_fp
          4. Protection visible in evidence -> likely_fp
          5. Confidence >= 0.80 + sensitive sink -> likely_tp
          6. Everything else               -> review
        """
        evidence = (f.evidence or "").lower()
        file_str = str(f.file).lower()
        (f.title or "").lower()

        # 1. Very low confidence -> the scanner itself doubts this finding
        if f.confidence < 0.20:
            return Verdict(
                "likely_fp", 0.85, f"Very low confidence ({f.confidence:.0%}) -- scanner uncertain"
            )

        # 2. A proven taint chain reaching a sensitive sink is strong evidence
        if f.flow_type == "taint" and f.taint_line:
            sink_name = (f.sink or "").lower()
            if cls._PROD_SINK.search(sink_name + " " + evidence):
                return Verdict(
                    "likely_tp", 0.88, f"Taint chain proven: line {f.taint_line} -> {f.sink}"
                )

        # 3. Findings inside test fixtures or vendor code are rarely real bugs
        if cls._TEST_PATH.search(file_str):
            return Verdict(
                "likely_fp", 0.75, "Path suggests test/vendor code -- verify before flagging"
            )

        # 4. A sanitizer or nonce check visible in the evidence snippet itself
        if cls._PROTECTION.search(evidence):
            return Verdict("likely_fp", 0.65, "Protection function visible in evidence snippet")

        # 5. High confidence plus a sensitive sink, even without a proven chain
        if (
            f.confidence >= 0.80
            and f.severity in ("CRITICAL", "HIGH")
            and cls._PROD_SINK.search((f.sink or "") + " " + evidence)
        ):
            return Verdict(
                "likely_tp",
                0.80,
                f"High confidence ({f.confidence:.0%}) + sensitive sink",
            )

        # 6. Anything else needs a human to look at it
        return Verdict("review", 0.50, "")

    @classmethod
    def filter_likely_fp(
        cls,
        findings: Sequence[Finding],
        *,
        threshold: float = 0.70,
    ) -> tuple[list[Finding], list[Finding]]:
        """
        Split findings into (kept, likely_false_positives).

        A finding is removed only if its Verdict is likely_fp AND that
        verdict's own confidence is at or above `threshold` -- a low-
        confidence FP guess is not enough to silently drop a finding.
        """
        kept, removed = [], []
        for f in findings:
            v = cls.classify(f)
            if v.label == "likely_fp" and v.confidence >= threshold:
                removed.append(f)
            else:
                kept.append(f)
        return kept, removed


# ---------------------------------------------------------------------------
# Markdown export of the triage queue
# ---------------------------------------------------------------------------


def triage_markdown(findings: Sequence[Finding]) -> str:
    """
    Export the manual-review queue as a Markdown table.
    Suitable for GitHub Issues and PR comments.
    """
    queue = manual_review_queue(findings, min_severity="HIGH")
    if not queue:
        return "## \u2705 No HIGH/CRITICAL findings\n"

    lines = [
        "## \U0001f50d Manual Review Queue\n",
        f"**{len(queue)} finding(s)** need manual review.\n",
        "| # | Sev | Rule | Location | Title | Auto-verdict |",
        "| :- | :- | :- | :- | :- | :- |",
    ]
    for i, f in enumerate(queue, 1):
        loc = f"`{str(f.file).replace(chr(92), '/')}:{f.line}`"
        verdict = AutoClassifier.classify(f)
        badge = (
            "\U0001f7e2 TP"
            if verdict.label == "likely_tp"
            else ("\U0001f534 FP?" if verdict.label == "likely_fp" else "\U0001f7e1 Review")
        )
        lines.append(f"| {i} | **{f.severity}** | `{f.rule_id}` | {loc} | {f.title} | {badge} |")
    lines.append("")
    lines.append("> Auto-verdict is a hint only. Always verify manually before acting.")
    return "\n".join(lines)
