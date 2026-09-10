"""
deep.py – same-file + cross-file call chain analysis and AUTH scoring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .project import ProjectIndex

_JWT_STRONG = re.compile(
    r"(JWT::decode|Firebase\\JWT|openssl_verify|['\"]exp['\"]|['\"]iss['\"]|RS256|HS256|JWKS)",
    re.I,
)
_JWT_WEAK = re.compile(r"(base64_decode|json_decode|explode\s*\(\s*['\"]\\.)", re.I)
_ALT_AUTH = re.compile(r"(get_payload|jwt_decode|verify_token|validate_token)\s*\(", re.I)

_FUNC = re.compile(
    r"(?:public|private|protected|static|\s)*function\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{",
    re.I | re.M,
)
_CALL = re.compile(
    r"(?:\$this\s*->|self\s*::|[A-Za-z_][A-Za-z0-9_]*\s*::)?\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_AUTH = re.compile(
    r"\b(check_ajax_referer|wp_verify_nonce|check_admin_referer|"
    r"current_user_can|is_user_logged_in|hash_equals)\s*\("
)
_SANITIZER = re.compile(
    r"\b(absint|intval|floatval|sanitize_text_field|sanitize_key|"
    r"sanitize_email|wc_clean|wc_get_var|wp_unslash|esc_url_raw|"
    r"filter_input|filter_var|wc_sanitize_order_id)\s*\("
)
_SENSITIVE = re.compile(
    r"\b("
    r"update_option|delete_option|add_option|"
    r"update_user_meta|delete_user_meta|wp_update_user|wp_insert_user|wp_delete_user|"
    r"wp_set_auth_cookie|wp_set_current_user|wp_signon|sign_in_user|register_new_user|merge_with_existing_user|set_tokens|"
    r"wc_create_order|wc_get_order|"
    r"\$wpdb\s*->\s*(update|insert|delete|query|replace)|"
    r"wp_mail|move_uploaded_file|file_put_contents|"
    r"wp_redirect|wp_safe_redirect"
    r")\s*\(",
    re.I,
)
_INPUT = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[")

_PROP_CALL = re.compile(
    r"\$this\s*->\s*[A-Za-z_][A-Za-z0-9_]*\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("
)

_NOISE = {
    "if",
    "for",
    "foreach",
    "while",
    "switch",
    "array",
    "list",
    "isset",
    "empty",
    "unset",
    "echo",
    "print",
    "return",
    "new",
    "function",
    "class",
    "public",
    "private",
    "protected",
    "static",
    "true",
    "false",
    "null",
    "define",
    "defined",
}


@dataclass
class FuncInfo:
    name: str
    body: str
    start_line: int
    calls: set[str] = field(default_factory=set)


@dataclass
class ChainAnalysis:
    has_auth: bool
    has_sensitive_sink: bool
    has_user_input: bool
    has_sanitizer: bool
    expanded_len: int
    callees: list[str]
    cross_file: bool = False
    has_alt_auth: bool = False
    path_summary: str = ""
    jwt_inspected: bool = False
    jwt_strong: bool = False
    jwt_weak_only: bool = False


@dataclass
class FileIndex:
    funcs: dict[str, FuncInfo] = field(default_factory=dict)
    text: str = ""
    file: str = ""

    def local_calls(self, name: str) -> set[str]:
        if name not in self.funcs:
            return set()
        return set(self.funcs[name].calls)


_BRACE = re.compile(r"[{}]")


def _extract_body(text: str, brace_pos: int, max_chars: int = 12000) -> str:
    """
    Extract a brace-matched block starting at `brace_pos` (the position of
    the opening '{').

    Uses a compiled regex to jump directly between successive '{'/'}'
    positions instead of checking every character in a Python while-loop.
    Brace-matching is inherently sequential (can't skip past a candidate
    without knowing the current depth), but the vast majority of
    characters in a real function body are NOT braces -- iterating one
    Python-level `text[i]` comparison per character has real interpreter
    overhead that a C-implemented regex scan over just the brace
    positions avoids. Measured ~5x faster on a realistic ~3000-character
    function body, with byte-identical output (including the
    unbalanced-braces/truncation-at-max_chars edge case).
    """
    end = min(len(text), brace_pos + max_chars)
    depth = 0
    for m in _BRACE.finditer(text, brace_pos, end):
        if m.group() == "{":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return text[brace_pos : m.end()]
    return text[brace_pos:end]


def index_file(text: str, file: str = "") -> FileIndex:
    idx = FileIndex(text=text, file=file)
    for m in _FUNC.finditer(text):
        name = m.group(1)
        brace = m.end() - 1
        body = _extract_body(text, brace)
        start_line = text.count("\n", 0, m.start()) + 1
        calls: set[str] = set()
        for cm in _CALL.finditer(body):
            callee = cm.group(1)
            if callee.lower() not in _NOISE and callee != name:
                calls.add(callee)
        idx.funcs[name] = FuncInfo(name=name, body=body, start_line=start_line, calls=calls)
    return idx


def expand_chain(
    name: str,
    file_idx: FileIndex,
    project: ProjectIndex | None = None,
    max_hops: int = 4,
) -> ChainAnalysis:
    """
    Expand name + callees up to max_hops.
    Prefer same-file bodies; fall back to project index (cross-file).
    """
    seen: set[str] = set()
    parts: list[str] = []
    callees: list[str] = []
    cross = False
    queue = [(name, 0)]

    while queue:
        cur, hop = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)

        body = None
        if cur in file_idx.funcs:
            body = file_idx.funcs[cur].body
            next_calls = file_idx.funcs[cur].calls
        elif project is not None:
            bodies = project.bodies_for(cur, prefer_file=file_idx.file, limit=1)
            if bodies:
                body = bodies[0]
                cross = True
                next_calls = {
                    cm.group(1)
                    for cm in _CALL.finditer(body)
                    if cm.group(1).lower() not in _NOISE and cm.group(1) != cur
                }
            else:
                next_calls = set()
        else:
            next_calls = set()

        if body:
            parts.append(body)
            if cur != name:
                callees.append(cur)

        if hop >= max_hops:
            continue
        for callee in next_calls:
            if callee not in seen:
                queue.append((callee, hop + 1))

    text = "\n".join(parts)
    has_alt = (
        bool(_ALT_AUTH.search(text))
        if "_ALT_AUTH" in dir()
        else bool(__import__("re").search(r"get_payload\s*\(", text))
    )
    try:
        has_alt = bool(_ALT_AUTH.search(text))
    except NameError:
        has_alt = bool(
            __import__("re").search(r"(get_payload|jwt_decode)\s*\(", text, __import__("re").I)
        )
    jwt_strong = False
    jwt_weak = False
    jwt_inspected = False
    # Follow token methods into project
    token_names = {
        "get_payload",
        "jwt_decode",
        "verify_token",
        "validate_token",
        "decode_token",
        "decode",
    }
    if project is not None:
        for tn in token_names:
            if tn in seen or tn in callees or has_alt:
                for body in project.bodies_for(tn, limit=2):
                    jwt_inspected = True
                    has_alt = True
                    if __import__("re").search(
                        r"(JWT::decode|Firebase|openssl_verify|['\"]exp['\"]|['\"]iss['\"]|RS256|HS256|JWKS)",
                        body,
                        __import__("re").I,
                    ):
                        jwt_strong = True
                    elif __import__("re").search(r"(base64_decode|json_decode)", body):
                        jwt_weak = True
                if jwt_inspected:
                    break
    if jwt_strong:
        jwt_weak = False
    return ChainAnalysis(
        has_auth=bool(_AUTH.search(text) or "__return_true" in text),
        has_sensitive_sink=bool(_SENSITIVE.search(text)),
        has_user_input=bool(_INPUT.search(text)),
        has_sanitizer=bool(_SANITIZER.search(text)),
        expanded_len=len(text),
        callees=callees,
        cross_file=cross or jwt_inspected,
        has_alt_auth=has_alt,
        path_summary=("JWT/token" if has_alt else ""),
        jwt_inspected=jwt_inspected,
        jwt_strong=jwt_strong,
        jwt_weak_only=jwt_weak and not jwt_strong,
    )


def resolve_callback_name(reg_window: str) -> str | None:
    m = re.search(
        r"add_action\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
        reg_window,
    )
    if m:
        return m.group(1)
    m = re.search(
        r"(?:array\s*\(|\[)\s*(?:\$this|__CLASS__)\s*,\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
        reg_window,
    )
    if m:
        return m.group(1)
    return None


def score_auth_finding(
    *, is_nopriv: bool, chain: ChainAnalysis, resolved: bool
) -> tuple[str, float, str]:
    if chain.has_auth:
        return ("INFO", 0.0, "")

    if getattr(chain, "has_alt_auth", False) and getattr(chain, "jwt_strong", False):
        return ("INFO", 0.22, "JWT handler shows signature or claim validation")
    if getattr(chain, "has_alt_auth", False) and getattr(chain, "jwt_weak_only", False):
        return (
            "MEDIUM",
            0.80 if resolved else 0.72,
            "token decoded without visible signature/exp validation",
        )
    if getattr(chain, "has_alt_auth", False):
        if is_nopriv and chain.has_sensitive_sink:
            return (
                "LOW",
                0.55 if resolved else 0.45,
                "public AJAX, no WP nonce, token/JWT present – review token validation",
            )
        return ("LOW", 0.48, "AJAX, no WP nonce, token/JWT present")

    if is_nopriv and chain.has_sensitive_sink and chain.has_user_input:
        return (
            "HIGH",
            0.92 if resolved else 0.85,
            "public AJAX, no auth, user input reaches sensitive sink",
        )
    if is_nopriv and chain.has_sensitive_sink:
        return (
            "HIGH",
            0.88 if resolved else 0.80,
            "public AJAX, no auth, sensitive sink in handler chain",
        )
    if is_nopriv and chain.has_user_input:
        return ("MEDIUM", 0.80 if resolved else 0.70, "public AJAX, no auth, reads user input")
    if is_nopriv:
        return ("MEDIUM", 0.72 if resolved else 0.55, "public AJAX, no visible auth")
    if chain.has_sensitive_sink and chain.has_user_input:
        return (
            "MEDIUM",
            0.78 if resolved else 0.68,
            "AJAX, no auth, user input reaches sensitive sink",
        )
    if chain.has_sensitive_sink:
        return (
            "MEDIUM",
            0.70 if resolved else 0.60,
            "AJAX, no auth, sensitive sink in handler chain",
        )
    return ("MEDIUM", 0.65 if resolved else 0.50, "AJAX, no visible auth")
