"""ajax.py -- cross-file chain + AUTH/data-flow correlation."""

from __future__ import annotations

import re

from ..deep import (
    ChainAnalysis,
    expand_chain,
    index_file,
    resolve_callback_name,
    score_auth_finding,
)
from ..models import Finding
from ..utils import line_number, snippet

_STATIC = re.compile(r"add_action\s*\(\s*['\"](wp_ajax(?:_nopriv)?_[^'\".]+)['\"]")
_DYNAMIC = re.compile(r"add_action\s*\(\s*['\"](wp_ajax(?:_nopriv)?_[^'\"]*)['\"]\s*\.")
_SAFE_ACTION = re.compile(r"(heartbeat|ping|keepalive|health.?check)", re.I)
_AUTH = re.compile(
    r"\b(check_ajax_referer|wp_verify_nonce|check_admin_referer|"
    r"current_user_can|is_user_logged_in|hash_equals)\s*\("
)
_INPUT = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[")
_SENSITIVE = re.compile(
    r"\b(update_option|delete_option|wp_update_user|wp_set_auth_cookie|"
    r"wp_set_current_user|\$wpdb\s*->\s*(update|insert|delete|query)|"
    r"wc_get_order|wp_redirect)\s*\(",
    re.I,
)


def _phpcs_auth(lines, line: int) -> bool:
    for i in (line - 1, line - 2):
        if 0 <= i < len(lines):
            low = lines[i].lower()
            if "phpcs:ignore" in low and any(
                k in low for k in ("nonce", "csrf", "capability", "permission", "auth")
            ):
                return True
    return False


def _extract_ajax_events(text: str) -> dict[str, bool]:
    events: dict[str, bool] = {}
    m = re.search(r"\$ajax_events\s*=\s*(?:array\s*\(|\[)(.+?)(?:\)|\]);", text, re.S)
    if not m:
        return events
    for em in re.finditer(
        r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*=>\s*(true|false|!0|!1|1|0)",
        m.group(1),
        re.I,
    ):
        events[em.group(1)] = em.group(2).lower() in ("true", "!0", "1")
    return events


def _chain_from_text(window: str) -> ChainAnalysis:
    return ChainAnalysis(
        has_auth=bool(_AUTH.search(window) or "__return_true" in window),
        has_sensitive_sink=bool(_SENSITIVE.search(window)),
        has_user_input=bool(_INPUT.search(window)),
        has_sanitizer=False,
        expanded_len=len(window),
        callees=[],
    )


def _message(chain: ChainAnalysis, detail: str) -> str:
    extras = []
    if chain.has_sensitive_sink:
        extras.append("sensitive sink in call chain")
    if chain.cross_file:
        extras.append("resolved across files")
    note = " · ".join(extras)
    suffix = f" ({note})" if note else ""
    return f"{detail}{suffix}. Auth may live in a parent class or vendor code – verify manually."


def scan_ajax(path, text, project=None) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    rel = str(path).replace("\\", "/")
    fidx = index_file(text, file=rel)
    seen: set[int] = set()

    # Skip matches inside comment lines (same reasoning as the _STATIC
    # loop below): a docblock or comment merely mentioning a dynamic
    # add_action(...) registration would otherwise generate a phantom
    # finding via the "not resolved" fallback branch.
    dyn = [
        m
        for m in _DYNAMIC.finditer(text)
        if not lines[line_number(text, m.start()) - 1].lstrip().startswith(("//", "#", "*", "/*"))
    ]
    dyn_lines = {line_number(text, m.start()) for m in dyn}

    if dyn:
        events = _extract_ajax_events(text)
        resolved_any = False
        for event_name, is_nopriv in events.items():
            # resolve in this file or project
            if event_name not in fidx.funcs and not (project and project.lookup(event_name)):
                continue
            resolved_any = True
            chain = expand_chain(event_name, fidx, project=project, max_hops=4)
            if chain.has_auth:
                continue
            severity, conf, detail = score_auth_finding(
                is_nopriv=is_nopriv, chain=chain, resolved=True
            )
            if severity == "INFO" or conf < 0.35:
                continue
            reg_line = line_number(text, dyn[0].start())
            findings.append(
                Finding(
                    rule_id="WC-AUTH-001",
                    severity=severity,
                    title=f"AJAX handler '{event_name}': {detail}",
                    file=str(path),
                    line=reg_line,
                    message=_message(chain, detail),
                    owasp="A01:2025-Broken Access Control",
                    confidence=round(conf, 2),
                    evidence=snippet(lines, reg_line),
                    source=("wp_ajax_nopriv_" if is_nopriv else "wp_ajax_") + event_name,
                    sink=f"method {event_name}()",
                )
            )
            seen.add(reg_line)

        if not resolved_any and dyn:
            line = line_number(text, dyn[0].start())
            if line not in seen and not _phpcs_auth(lines, line):
                findings.append(
                    Finding(
                        rule_id="WC-AUTH-001",
                        severity="LOW",
                        title="Dynamic AJAX registration – handlers not resolved",
                        file=str(path),
                        line=line,
                        message=(
                            "Could not resolve $ajax_events methods in this plugin. "
                            "Manual review required – not a confirmed issue."
                        ),
                        owasp="A01:2025-Broken Access Control",
                        confidence=0.42,
                        evidence=snippet(lines, line),
                        source="wp_ajax_* (dynamic)",
                        sink="AJAX callback",
                    )
                )
                seen.add(line)

    for match in _STATIC.finditer(text):
        action = match.group(1)
        line = line_number(text, match.start())
        if line in seen or line in dyn_lines:
            continue
        if _SAFE_ACTION.search(action):
            continue
        if _phpcs_auth(lines, line):
            continue
        # Skip matches inside comment lines. _STATIC is a plain text scan
        # (not AST-based), so without this a docblock or inline comment
        # merely MENTIONING add_action('wp_ajax_nopriv_...', ...) --
        # explaining what NOT to do, or documenting a past fix -- generates
        # a phantom finding. Found for real while writing a test fixture.
        raw_line = lines[line - 1] if 0 < line <= len(lines) else ""
        if raw_line.lstrip().startswith(("//", "#", "*", "/*")):
            continue

        is_nopriv = "wp_ajax_nopriv_" in action
        reg_window = text[match.start() : match.start() + 600]
        cb = resolve_callback_name(reg_window)

        if cb and (cb in fidx.funcs or (project and project.lookup(cb))):
            chain = expand_chain(cb, fidx, project=project, max_hops=4)
            resolved = True
        else:
            chain = _chain_from_text(text[match.end() : match.end() + 1800])
            resolved = False

        if chain.has_auth:
            continue
        severity, conf, detail = score_auth_finding(
            is_nopriv=is_nopriv, chain=chain, resolved=resolved
        )
        if severity == "INFO" or conf < 0.35:
            continue

        findings.append(
            Finding(
                rule_id="WC-AUTH-001",
                severity=severity,
                title=f"AJAX handler: {detail}",
                file=str(path),
                line=line,
                message=_message(chain, detail),
                owasp="A01:2025-Broken Access Control",
                confidence=round(conf, 2),
                evidence=snippet(lines, line),
                source=action,
                sink=f"method {cb}()" if cb else "AJAX callback",
            )
        )
        seen.add(line)

    return findings
