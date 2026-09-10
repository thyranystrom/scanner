"""
confidence.py
-------------
Rule-based confidence framework that replaces hardcoded floats across all
rule modules.

Model
-----
Every finding is built from a set of named *signals* (the S.* constants
below). A Scorer starts from a base probability and adds or subtracts a
fixed weight per signal, then clamps the result to [MIN, MAX].

Three signal categories:
  BOOST  – increases confidence (a clear chain of evidence)
  REDUCE – decreases confidence (ambiguity, or evidence against the finding)
  CAP    – imposes a hard ceiling regardless of other signals (used when the
           analysis itself has a structural limitation, e.g. resolution
           was limited to a single file, so full confidence is never
           warranted no matter how strong the local signals look)

Usage
-----
    from ..confidence import Scorer, S
    conf = Scorer(base=0.50).add(S.TAINT_CHAIN, S.DIRECT_USER_INPUT).score()

Per-rule-type convenience functions live at the bottom of this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class S:
    """Signal name constants — pass these to Scorer.add() / .remove()."""

    # ── Boost ──────────────────────────────────────────────────────────────
    TAINT_CHAIN = "taint_chain"  # dataflow proved a source -> sink path
    DIRECT_USER_INPUT = "direct_user_input"  # a superglobal appears directly on the sink line
    SENSITIVE_SINK = "sensitive_sink"  # DB write, auth check, redirect, etc.
    CROSS_FILE = "cross_file"  # taint was resolved across a file boundary
    NOPRIV_AJAX = "nopriv_ajax"  # wp_ajax_nopriv_ handler (reachable while logged out)
    NO_AUTH_CHECK = "no_auth_check"  # no nonce/capability check found in scope
    LIVE_CREDENTIAL = "live_credential"  # matches a known live-key format (sk_live_, AKIA, ghp_)
    HARDCODED_IN_CODE = "hardcoded_in_code"  # a literal string, not read from env/option
    DANGEROUS_FN = "dangerous_fn"  # eval/exec/shell_exec present
    WEAK_CRYPTO = "weak_crypto"  # md5/sha1 used in a security-relevant context
    UNSERIALIZE_TAINTED = "unserialize_tainted"  # unserialize() near user-controlled input
    SSRF_TAINTED_URL = "ssrf_tainted_url"  # outbound HTTP call with an attacker-influenced URL

    # ── Reduce ─────────────────────────────────────────────────────────────
    NONCE_PRESENT = "nonce_present"  # a CSRF nonce check exists (does not imply sanitization)
    PREPARE_NEARBY = "prepare_nearby"  # $wpdb->prepare() is used nearby
    ESCAPE_ON_LINE = "escape_on_line"  # esc_html()/esc_attr() wraps the value on the same line
    LITERAL_ASSIGN = "literal_assign"  # the variable was assigned from a string constant
    PHPCS_SUPPRESS = "phpcs_suppress"  # a phpcs:ignore directive covers this line
    IN_COMMENT = "in_comment"  # the match falls inside a comment
    ONLY_DYNAMIC = "only_dynamic"  # a dynamic registration pattern that could not be resolved
    NO_SENSITIVE_SINK = "no_sensitive_sink"  # a handler was found but performs no risky operation
    SANITIZER_PRESENT = "sanitizer_present"  # a sanitizer exists in scope (on a different line)
    PLACEHOLDER_VALUE = "placeholder_value"  # looks like an example/dummy value, not a real secret

    # ── Cap ────────────────────────────────────────────────────────────────
    CAP_UNRESOLVED = "cap_unresolved"  # the target callback could not be found in the project index
    CAP_SINGLE_FILE = "cap_single_file"  # analysis was limited to a single file's local context


_WEIGHTS: dict[str, float] = {
    S.TAINT_CHAIN: +0.25,
    S.DIRECT_USER_INPUT: +0.18,
    S.SENSITIVE_SINK: +0.12,
    S.CROSS_FILE: +0.08,
    S.NOPRIV_AJAX: +0.10,
    S.NO_AUTH_CHECK: +0.15,
    S.LIVE_CREDENTIAL: +0.20,
    S.HARDCODED_IN_CODE: +0.12,
    S.DANGEROUS_FN: +0.10,
    S.WEAK_CRYPTO: +0.05,
    S.UNSERIALIZE_TAINTED: +0.20,
    S.SSRF_TAINTED_URL: +0.15,
    # reduces
    S.NONCE_PRESENT: -0.10,
    S.PREPARE_NEARBY: -0.20,
    S.ESCAPE_ON_LINE: -0.30,
    S.LITERAL_ASSIGN: -0.20,
    S.PHPCS_SUPPRESS: -0.25,
    S.IN_COMMENT: -0.50,
    S.ONLY_DYNAMIC: -0.12,
    S.NO_SENSITIVE_SINK: -0.08,
    S.SANITIZER_PRESENT: -0.12,
    S.PLACEHOLDER_VALUE: -0.20,
}

_CAPS: dict[str, float] = {
    S.CAP_UNRESOLVED: 0.55,
    S.CAP_SINGLE_FILE: 0.80,
}

_MIN = 0.05
_MAX = 0.98


@dataclass
class Scorer:
    """A fluent confidence-score builder."""

    base: float = 0.50
    _signals: list = field(default_factory=list)

    def add(self, *signals: str) -> Scorer:
        for s in signals:
            if s not in self._signals:
                self._signals.append(s)
        return self

    def remove(self, *signals: str) -> Scorer:
        self._signals = [s for s in self._signals if s not in signals]
        return self

    def score(self) -> float:
        """
        Sum the base value with every added signal's weight, then clamp the
        result to the tightest applicable cap and to the global [MIN, MAX]
        range. Rounded to 3 decimal places purely for readable output.
        """
        total = self.base
        cap = _MAX
        for sig in self._signals:
            if sig in _WEIGHTS:
                total += _WEIGHTS[sig]
            if sig in _CAPS:
                cap = min(cap, _CAPS[sig])
        return round(max(_MIN, min(cap, total)), 3)

    def explain(self) -> str:
        """
        Return a human-readable breakdown of how the final score was
        reached — useful when debugging why a specific finding got the
        confidence it did, or when writing a regression test that asserts
        on the reasoning rather than just the final number.
        """
        lines = [f"base={self.base:.3f}"]
        total = self.base
        for sig in self._signals:
            if sig in _WEIGHTS:
                w = _WEIGHTS[sig]
                total += w
                lines.append(f"  {'+' if w >= 0 else ''}{w:.3f}  {sig}")
        cap = min((_CAPS[s] for s in self._signals if s in _CAPS), default=_MAX)
        lines.append(f"  -> raw={total:.3f}  cap={cap:.3f}  final={self.score():.3f}")
        return "\n".join(lines)


# ── Per-rule-type convenience helpers ────────────────────────────────────────
# Each function below encodes one rule module's specific scoring logic in one
# place, so the rule module itself only needs to describe *which* signals
# apply to a given finding, not *how much* each one is worth.


def score_input_direct(*, nonce_present: bool, sanitizer_in_scope: bool) -> float:
    """Score a direct, unsanitized superglobal access (WC-INPUT-00x)."""
    return (
        Scorer(base=0.38)
        .add(*([S.NONCE_PRESENT] if nonce_present else []))
        .add(*([S.SANITIZER_PRESENT] if sanitizer_in_scope else []))
        .add(S.CAP_SINGLE_FILE)  # this check never sees cross-file context
        .score()
    )


def score_output(
    *,
    taint_chain: bool,
    escape_on_line: bool,
    literal_assign: bool,
    phpcs_suppress: bool,
    nonce_present: bool,
) -> tuple[float, str]:
    """
    Score an unescaped-output finding (WC-OUTPUT-001 / WC-XSS-001).

    Returns (confidence, severity) as a pair, since the severity threshold
    depends on the same scored value: a proven taint chain reaching a
    reasonable confidence is escalated to MEDIUM, otherwise the finding is
    kept at LOW or INFO to reflect genuine uncertainty.
    """
    s = (
        Scorer(base=0.36)
        .add(*([S.TAINT_CHAIN] if taint_chain else []))
        .add(*([S.ESCAPE_ON_LINE] if escape_on_line else []))
        .add(*([S.LITERAL_ASSIGN] if literal_assign else []))
        .add(*([S.PHPCS_SUPPRESS] if phpcs_suppress else []))
        .add(*([S.NONCE_PRESENT] if nonce_present else []))
    )
    conf = s.score()
    sev = "MEDIUM" if (taint_chain and conf >= 0.50) else ("LOW" if conf >= 0.38 else "INFO")
    return conf, sev


def score_secret(
    *,
    live_credential: bool,
    hardcoded: bool,
    in_comment: bool,
    phpcs_suppress: bool,
    placeholder: bool = False,
) -> float:
    """Score a possible hardcoded-secret finding (WC-SECRET-001/002)."""
    return (
        Scorer(base=0.46)
        .add(*([S.LIVE_CREDENTIAL] if live_credential else []))
        .add(*([S.HARDCODED_IN_CODE] if hardcoded else []))
        .add(*([S.IN_COMMENT] if in_comment else []))
        .add(*([S.PHPCS_SUPPRESS] if phpcs_suppress else []))
        .add(*([S.PLACEHOLDER_VALUE] if placeholder else []))
        .score()
    )


def score_sql(*, taint_chain: bool, prepare_nearby: bool, direct_input: bool) -> float:
    """Score a potential SQL injection finding (WC-SQL-001)."""
    return (
        Scorer(base=0.44)
        .add(*([S.TAINT_CHAIN] if taint_chain else []))
        .add(*([S.DIRECT_USER_INPUT] if direct_input else []))
        .add(*([S.PREPARE_NEARBY] if prepare_nearby else []))
        .score()
    )
