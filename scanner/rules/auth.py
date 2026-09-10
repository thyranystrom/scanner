import re

from ..models import Finding
from ..utils import line_number, snippet

# permission_callback set to a known "always allow" no-op. __return_true
# is a WordPress core convenience function that unconditionally returns
# true -- using it here disables access control entirely while still
# satisfying a naive "is permission_callback present?" check.
_PERMISSION_ALWAYS_TRUE = re.compile(
    r"permission_callback['\"]?\s*(?:=>|:)\s*['\"]__return_true['\"]"
)


def scan_rest_and_admin(path, text, project=None):
    findings = []
    lines = text.splitlines()

    for m in re.finditer(r"register_rest_route\s*\(", text):
        line = line_number(text, m.start())
        context = text[m.start() : m.start() + 4000]

        if "permission_callback" not in context:
            findings.append(
                Finding(
                    rule_id="WC-AUTH-002",
                    severity="HIGH",
                    title="REST route may lack permission_callback",
                    file=str(path),
                    line=line,
                    message=(
                        "Review the complete register_rest_route() declaration. "
                        "WordPress REST routes should define an intentional "
                        "permission_callback."
                    ),
                    owasp="A01:2025-Broken Access Control",
                    confidence=0.93,
                    evidence=snippet(lines, line),
                    source="register_rest_route()",
                    sink="REST endpoint",
                )
            )
        elif _PERMISSION_ALWAYS_TRUE.search(context):
            # A permission_callback key IS present, but its value is a
            # known "always allow" no-op -- __return_true is a WordPress
            # core function that unconditionally returns true regardless
            # of who's asking. This satisfies a naive "does the key
            # exist?" check while providing exactly zero access control,
            # which is functionally identical to having no
            # permission_callback at all (arguably worse: it looks
            # intentional). Found as a real detection gap: the presence
            # check alone treated this as safe.
            findings.append(
                Finding(
                    rule_id="WC-AUTH-002",
                    severity="HIGH",
                    title="REST route permission_callback always allows access",
                    file=str(path),
                    line=line,
                    message=(
                        "permission_callback is set to __return_true (or an "
                        "equivalent always-true value), which grants access "
                        "unconditionally regardless of who makes the request. "
                        "This provides no actual access control."
                    ),
                    owasp="A01:2025-Broken Access Control",
                    confidence=0.85,
                    evidence=snippet(lines, line),
                    source="register_rest_route()",
                    sink="REST endpoint",
                )
            )

    for m in re.finditer(r"add_action\s*\(\s*['\"]admin_post_[^'\"]+", text):
        line = line_number(text, m.start())
        context = text[m.start() : m.start() + 3000]

        has_capability = bool(re.search(r"current_user_can\s*\(", context))
        has_nonce = bool(
            re.search(r"check_admin_referer|check_ajax_referer|wp_verify_nonce", context)
        )
        has_login = bool(re.search(r"is_user_logged_in\s*\(", context))

        if not (has_capability or has_nonce or has_login):
            findings.append(
                Finding(
                    rule_id="WC-AUTH-003",
                    severity="MEDIUM",
                    title="admin-post handler has no visible authorization check",
                    file=str(path),
                    line=line,
                    message=(
                        "Review the callback. A nonce protects request origin but "
                        "does not by itself establish user capability; sensitive "
                        "actions should also enforce authorization/ownership."
                    ),
                    owasp="A01:2025-Broken Access Control",
                    confidence=0.84,
                    evidence=snippet(lines, line),
                    source="admin_post_*",
                    sink="admin-post callback",
                )
            )

    return findings
