"""
owasp_top10.py
-------------------------
OWASP Top 10 (2025) rules for WordPress/WooCommerce plugins that don't
have a dedicated module of their own.

Covers:
  == SSRF (WC-OWASP-001 -> A01) ==
  Old logic: flagged every wp_remote_get/post call that contained ANY
  variable at all ($this included). That produced three false positives
  found while validating against a production plugin (Klarna Payments
  for WooCommerce):
    - A hardcoded S3 URL assigned to $args (a result variable, not the URL)
    - $this->jwks_url  (configuration, not user input)
    - plugin_dir_url(__FILE__) (a WordPress framework constant)

  New logic -- four levels, all must fail to flag anything:
    1. URL sniffing: is the URL argument a plain string literal? -> skip
    2. Taint check (dataflow): is the URL variable tainted from $_GET/$_POST?
       Yes -> HIGH, conf 0.92
    3. Configuration check: does the URL come from get_option/settings/config?
       Yes -> treat as safe and skip
    4. Some other dynamic variable remains: MEDIUM, conf 0.48 (flagged for
       manual review rather than silently ignored)

  == md5/sha1 context awareness ==
  A checksum-style usage context (cart_hash, session_hash, etc.) lowers
  confidence to 0.40 -- MD5 used purely as a non-cryptographic checksum is
  not the same security problem as MD5 used to hash a password.

  == phpcs:ignore ==
  Also checked on the same line as the finding (an inline comment), not
  just on the lines above it.
"""

import re
from pathlib import Path

from ..dataflow import analyze, resolve_source_file
from ..models import Finding
from ..utils import snippet

# ── Helper patterns ──────────────────────────────────────────────────────

_SUPERGLOBAL = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\s*\[")
_CONFIG_SOURCE = re.compile(
    r"\b(get_option|get_transient|WP_HTTP_TESTCASE|plugin_dir_url|plugins_url"
    r"|home_url|site_url|admin_url|includes_url|content_url|wp_upload_dir"
    r"|get_site_url|get_home_url|rest_url|__FILE__|__DIR__)\b",
    re.I,
)
_LITERAL_URL = re.compile(r"""['"](https?://[^'"]{8,})['"]""")

# Does the URL come from a class property (e.g. $this->api_url)?
# These are configuration, not user input, in the overwhelming majority of cases.
_CLASS_PROP = re.compile(r"\$this\s*->\s*\w+")
_CLASS_CONST = re.compile(r"(?:self|static|[A-Z][A-Za-z0-9_]*)\s*::\s*[A-Z][A-Z0-9_]+")

# Non-password context (cache key, signature token, etc.)
_CHECKSUM_CTX = re.compile(
    r"(checksum|cache[_-]?key|transient|etag|cart_hash|session_hash|"
    r"fingerprint|signature|implode\s*\(|sprintf\s*\(|option[_-]?name|"
    r"mutation_lock|context_cache|cache_prefix|lookup_key|"
    r"get_context_cache|get_mutation_lock)",
    re.I,
)

# Verification/authentication context: overrides _CHECKSUM_CTX above. If a
# hash is compared via hash_equals()/a named verify/validate function, or
# checked against an externally-supplied signature header/parameter, the
# hash IS being trusted as a security control (proving a request wasn't
# forged or tampered with) -- MD5's weakness is a real concern here even
# though the word "signature" is present, unlike the plain-identification
# case _CHECKSUM_CTX's "signature" entry exists for (e.g. a hash used only
# to correlate/identify an object, never compared against untrusted input).
# Without this override, a genuine MD5-based webhook-signature check --
# `if (!hash_equals($expected, $_SERVER['HTTP_X_SIGNATURE'])) { deny(); }`
# -- was silently downgraded to LOW purely because "signature" matched.
_VERIFY_CTX = re.compile(
    r"(hash_equals\s*\(|verify_signature|validate_signature|"
    r"\$_(SERVER|POST|GET|REQUEST)\s*\[\s*['\"]\w*signature)",
    re.I,
)

# ── Per-line scan patterns, precompiled once at import time ────────────────
#
# The main scan loop below runs every one of these regexes against EVERY
# line of EVERY file. Before this section existed, each pattern was passed
# as a literal string to the module-level re.search(pattern, line) function
# on every call -- profiling a real 202-file scan showed roughly a million
# calls into re's internal compile-cache-lookup machinery, which is fast
# per call but adds up across that many invocations. Precompiling once and
# calling the resulting Pattern object's .search()/.match() directly skips
# that wrapper overhead entirely. This is a pure performance change; every
# pattern below is byte-for-byte identical to its previous inline form.
_MD5_SHA1 = re.compile(r"\b(md5|sha1)\s*\(", re.I)
_PASSWORD_CTX = re.compile(
    r"(?:^|[^A-Za-z0-9_])(password|passwd|pwd|wp_hash_password|password_hash|"
    r"password_verify|user_pass|db_password|admin_password)(?:[^A-Za-z0-9_]|$)",
    re.I,
)

_WP_DEBUG_TRUE = re.compile(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)")
_PHPINFO = re.compile(r"\bphpinfo\s*\(", re.I)
_UNSERIALIZE = re.compile(r"\bunserialize\s*\(")
_REMOTE_FN = re.compile(r"(wp_remote_get|wp_remote_post|curl_exec)")
_DYNAMIC_INCLUDE_1 = re.compile(
    r"\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)"
)
_DYNAMIC_INCLUDE_2 = re.compile(
    r"\b(include|require|include_once|require_once)\s+\$_(GET|POST|REQUEST)"
)
_SKIP_FLAG_DEFINE = re.compile(
    r"define\s*\(\s*['\"]SKIP_(AUTH|NONCE|CAPABILITY|CSRF|PERMISSION)['\"]\s*,\s*true", re.I
)
_SKIP_FLAG_VAR = re.compile(r"\$disable_(auth|nonce|csrf|permission)\s*=\s*true", re.I)
_TODO_SECURITY = re.compile(
    r"//\s*(TODO|FIXME|HACK).*?\b(secur|auth|nonce|csrf|permission|vulnerab)", re.I
)
_PASSWORD_CMP_1 = re.compile(r"\$\w*(pass|pwd|password)\w*\s*(===|==|!=|!==)", re.I)
_PASSWORD_CMP_2 = re.compile(r"(===|==)\s*\$\w*(pass|pwd|password)\w*", re.I)
_SECURE_HASH_API = re.compile(r"wp_check_password|password_verify|wp_hash_password")
_WP_DIE_DENIAL = re.compile(
    r"wp_die\s*\(\s*['\"][^'\"]*(denied|forbidden|unauthorized|not allowed|access)", re.I
)
_JSON_ERROR_DENIAL = re.compile(
    r"wp_send_json_error\s*\(\s*['\"][^'\"]*(denied|forbidden|unauthorized|nonce|bad_nonce)", re.I
)
_JSON_ERROR_BAD_NONCE = re.compile(r"wp_send_json_error\s*\(\s*['\"]bad_nonce['\"]", re.I)
_AUTH_CHECK_FN = re.compile(
    r"(!\s*)?(wp_verify_nonce|check_ajax_referer|check_admin_referer|"
    r"current_user_can|user_can)\s*\(",
    re.I,
)
_LOG_CALL = re.compile(r"error_log\s*\(|wc_get_logger|wc_logger|->(error|warning|info)", re.I)
_EMPTY_CATCH = re.compile(r"catch\s*\(\s*\w+\s+\$\w+\s*\)\s*\{\s*\}")
_AT_SUPPRESSED = re.compile(
    r"@\s*(file_get_contents|fopen|unserialize|include|require|mysqli_query|curl_exec)\s*\("
)
_DIE_RAW_INPUT = re.compile(r"\b(die|exit)\s*\(\s*\$_(GET|POST|REQUEST)")
_DYNAMIC_VAR = re.compile(r"\$[A-Za-z_]\w*")
_REMOTE_CALL_ARG = re.compile(
    r"(?:wp_remote_get|wp_remote_post|curl_setopt|curl_exec)\s*\(\s*(.{1,200})"
)
_VAR_NAMES = re.compile(r"\$([A-Za-z_]\w*)")


def _phpcs_on_line(lines: list, line_no: int) -> bool:
    """True if phpcs:ignore appears on this line or one of the two lines above."""
    for i in (line_no - 1, line_no - 2, line_no - 3):
        if 0 <= i < len(lines) and "phpcs:ignore" in lines[i].lower():
            return True
    return False


# Lightweight pattern for tracking user-controlled variables without
# invoking the full dataflow engine -- used as a supplement when a variable
# assignment happens just outside the dataflow analysis window.
_TAINT_ASSIGN = re.compile(
    r"\$([A-Za-z_]\w*)\s*=\s*(?:.*?\$_(GET|POST|REQUEST|COOKIE)|"
    r"\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
)


def _ssrf_confidence(line: str, context_window: str, tainted_vars: set) -> tuple[str, float, bool]:
    """
    Return (severity, confidence, should_skip) for one wp_remote_get/post call.

    Logic (evaluated in priority order):
      1. URL is a plain string literal -> always skip
      2. URL comes from a WP constant/config/class property -> skip
      3. A superglobal appears directly in the URL argument -> HIGH 0.92
      4. A tainted variable (via dataflow OR local taint tracking) -> HIGH 0.92
      5. Some other dynamic variable remains -> MEDIUM 0.48
    """
    # Extract the URL argument by looking for the first argument of the call.
    url_arg_m = _REMOTE_CALL_ARG.search(line + "\n" + context_window[:400])
    url_arg = url_arg_m.group(1) if url_arg_m else line

    # 1. A hardcoded URL string is not attacker-controlled.
    if _LITERAL_URL.search(url_arg):
        return "", 0.0, True

    # 2. The URL comes from a recognized WP constant or config source -- not SSRF.
    if (
        _CONFIG_SOURCE.search(url_arg)
        or _CLASS_PROP.search(url_arg)
        or _CLASS_CONST.search(url_arg)
    ):
        return "", 0.0, True

    # 3. A superglobal appears directly inside the call arguments.
    if _SUPERGLOBAL.search(url_arg):
        return "HIGH", 0.92, False

    # 4a. Check whether any variable in the URL argument was proven tainted
    #     by the full AST-based dataflow analysis.
    vars_in_url = re.findall(r"\$([A-Za-z_]\w*)", url_arg[:200])
    for v in vars_in_url:
        if v in tainted_vars:
            return "HIGH", 0.92, False

    # 4b. Local taint tracking: check the context window for $var = $_GET[...]
    for m in _TAINT_ASSIGN.finditer(context_window):
        assigned_var = m.group(1)
        if assigned_var in vars_in_url:
            return "HIGH", 0.92, False

    # 5. Some other dynamic variable remains -- could be configuration, low confidence.
    if re.search(r"\$[A-Za-z_]\w*", url_arg):
        return "MEDIUM", 0.48, False

    return "", 0.0, True


def scan_owasp_top10(
    file_path: str | Path,
    code: str | None = None,
    project=None,
    **kwargs,
) -> list[Finding]:
    findings: list[Finding] = []
    path_str = str(file_path)

    actual_code = code or ""
    if not actual_code and Path(path_str).is_file():
        try:
            actual_code = Path(path_str).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            actual_code = ""

    lines = actual_code.splitlines()
    seen_lines: set[int] = set()

    # Run dataflow analysis once for the whole file. The SSRF rule below
    # uses this to determine whether a URL variable traces back to user input.
    df_results = analyze(
        actual_code, source_file=resolve_source_file(path_str, project), project=project
    )
    tainted_vars = {r.var_name for r in df_results}

    def add(line_no: int, **kw) -> None:
        if line_no not in seen_lines and not _phpcs_on_line(lines, line_no):
            seen_lines.add(line_no)
            findings.append(
                Finding(
                    file=path_str,
                    line=line_no,
                    evidence=snippet(lines, line_no),
                    **kw,
                )
            )

    for idx, line in enumerate(lines, start=1):
        line.lower()

        # Skip comment lines -- the regex could otherwise match a function
        # name that only appears inside a doc-block.
        stripped = line.lstrip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue

        # -- A04: Weak hashing --
        m = _MD5_SHA1.search(line)
        if m:
            fn = m.group(1).lower()
            # Checksum context: MD5 used as a cache/cart key is not a security problem.
            ctx = " ".join(lines[max(0, idx - 3) : idx + 3])
            is_verify = bool(_VERIFY_CTX.search(ctx))
            is_checksum = bool(_CHECKSUM_CTX.search(ctx)) and not is_verify
            is_password = bool(_PASSWORD_CTX.search(ctx)) or is_verify
            if is_password:
                conf, sev = 0.92, "HIGH"
            elif is_checksum:
                conf, sev = 0.40, "LOW"
            else:
                conf, sev = 0.70, "MEDIUM"
            if is_password:
                msg = (
                    f"{fn.upper()} used near password context — cryptographically "
                    "broken for password storage. Use wp_hash_password() / password_hash()."
                )
            elif is_checksum:
                msg = (
                    f"{fn.upper()} used as checksum/cache/signature key — low security "
                    "risk for non-password use; prefer hash('sha256', ...) for new code."
                )
            else:
                msg = (
                    f"{fn.upper()} detected. Prefer hash('sha256', ...) unless this is a "
                    "non-security checksum; do not use for passwords."
                )
            add(
                idx,
                rule_id="WC-OWASP-004",
                title="Weak Cryptographic Hash Function",
                severity=sev,
                message=msg,
                owasp="A04:2025-Cryptographic Failures",
                confidence=conf,
                source=fn,
                sink="weak hash",
            )

        # -- A02: WP_DEBUG left enabled in production --
        if _WP_DEBUG_TRUE.search(line):
            add(
                idx,
                rule_id="WC-OWASP-002",
                title="Debug Mode Enabled",
                severity="LOW",
                message=(
                    "WP_DEBUG is set to true. This exposes stack traces and "
                    "file paths to end users. Remove before deploying to production."
                ),
                owasp="A02:2025-Security Misconfiguration",
                confidence=0.90,
                source="WP_DEBUG=true",
                sink="debug output",
            )

        # -- A02: phpinfo() disclosure --
        if _PHPINFO.search(line):
            add(
                idx,
                rule_id="WC-OWASP-002",
                title="phpinfo() Call Found",
                severity="MEDIUM",
                message=(
                    "phpinfo() reveals server configuration, PHP version, loaded "
                    "extensions and environment variables. Remove from production."
                ),
                owasp="A02:2025-Security Misconfiguration",
                confidence=0.95,
                source="phpinfo()",
                sink="information disclosure",
            )

        # -- A08: unserialize() --
        if _UNSERIALIZE.search(line):
            ctx = actual_code[max(0, actual_code.find(line) - 200) : actual_code.find(line) + 400]
            has_user = bool(_SUPERGLOBAL.search(ctx))
            add(
                idx,
                rule_id="WC-OWASP-008",
                title="Insecure Deserialization",
                severity="CRITICAL" if has_user else "HIGH",
                message=(
                    "unserialize() with untrusted data can lead to Remote Code Execution. "
                    "Use json_decode() or verify data with a HMAC before deserializing."
                    + (" User-controlled input detected nearby." if has_user else "")
                ),
                owasp="A08:2025-Software or Data Integrity Failures",
                confidence=0.90 if has_user else 0.75,
                source="user input" if has_user else "unknown source",
                sink="unserialize()",
            )

        # -- SSRF (mapped to A01:2025-Broken Access Control; no standalone SSRF in Top 10 2025) --
        # Requires a proven taint chain or a direct superglobal in the URL
        # argument. Configuration sources (plugin_dir_url, get_option,
        # $this->prop) are suppressed.
        if any(fn in line for fn in ("wp_remote_get", "wp_remote_post", "curl_exec")):
            # Build a context window that also covers multi-line calls.
            pos = actual_code.find(line)
            ctx_window = actual_code[max(0, pos - 100) : pos + 500] if pos >= 0 else line
            fn_match = _REMOTE_FN.search(line)
            fn_name = fn_match.group(0) if fn_match else "wp_remote_get"

            severity, conf, skip = _ssrf_confidence(line, ctx_window, tainted_vars)
            if not skip:
                add(
                    idx,
                    rule_id="WC-OWASP-001",
                    title="Potential Server-Side Request Forgery (SSRF)",
                    severity=severity,
                    message=(
                        "External HTTP call where the URL may be influenced by "
                        "user-controlled data. Validate and allowlist URLs before "
                        "making outbound requests."
                        if severity == "HIGH"
                        else "External HTTP call with a dynamic URL. Verify the URL "
                        "cannot be influenced by user input. If the URL is fixed "
                        "or comes from plugin configuration, this is likely a "
                        "false positive."
                    ),
                    owasp="A01:2025-Broken Access Control",
                    confidence=conf,
                    source="tainted URL" if severity == "HIGH" else "dynamic URL",
                    sink=fn_name,
                )

        # ── A05:2025-Injection (dynamic include / require) ─────────────────
        if _DYNAMIC_INCLUDE_1.search(line) or _DYNAMIC_INCLUDE_2.search(line):
            add(
                idx,
                rule_id="WC-OWASP-005",
                title="Dynamic include/require of user input",
                severity="HIGH",
                message=(
                    "include/require uses user-controlled input. This can lead to "
                    "local/remote file inclusion. Never include paths from $_GET/$_POST."
                ),
                owasp="A05:2025-Injection",
                confidence=0.88,
                source="user input",
                sink="include/require",
            )

        # ── A06:2025-Insecure Design ──────────────────────────────────────
        if _SKIP_FLAG_DEFINE.search(line) or _SKIP_FLAG_VAR.search(line):
            add(
                idx,
                rule_id="WC-OWASP-006",
                title="Insecure design: security control disabled by flag",
                severity="HIGH",
                message=(
                    "A hard-coded flag appears to disable authentication, nonce, or "
                    "CSRF checks. Remove or gate strictly to non-production environments."
                ),
                owasp="A06:2025-Insecure Design",
                confidence=0.75,
                source="config/flag",
                sink="security bypass",
            )
        if _TODO_SECURITY.search(line):
            add(
                idx,
                rule_id="WC-OWASP-006",
                title="Insecure design: unresolved security TODO/FIXME",
                severity="LOW",
                message="Security-related TODO/FIXME left in code. Resolve before release.",
                owasp="A06:2025-Insecure Design",
                confidence=0.40,
                source="comment",
                sink="design debt",
            )

        # ── A07:2025-Authentication Failures ──────────────────────────────
        if (
            _PASSWORD_CMP_1.search(line) or _PASSWORD_CMP_2.search(line)
        ) and not _SECURE_HASH_API.search(line):
            add(
                idx,
                rule_id="WC-OWASP-007",
                title="Authentication: password compared without secure hash API",
                severity="HIGH",
                message=(
                    "Password appears compared with ==/===. "
                    "Use wp_check_password() or password_verify()."
                ),
                owasp="A07:2025-Authentication Failures",
                confidence=0.70,
                source="password variable",
                sink="direct compare",
            )

        # ── A09:2025-Security Logging and Alerting Failures ───────────────
        # Do NOT flag normal nonce/capability rejection branches:
        #   if ( ! wp_verify_nonce(...) ) { wp_send_json_error('bad_nonce'); }
        # Those are correct authz behaviour, not a logging vulnerability.
        if (
            _WP_DIE_DENIAL.search(line)
            or _JSON_ERROR_DENIAL.search(line)
            or _JSON_ERROR_BAD_NONCE.search(line)
        ):
            window_before = "\n".join(lines[max(0, idx - 8) : idx])
            # Skip if this is the failure branch of a nonce / capability check
            if _AUTH_CHECK_FN.search(window_before):
                pass  # intentional: do not flag
            else:
                window = "\n".join(lines[max(0, idx - 10) : min(len(lines), idx + 3)])
                if not _LOG_CALL.search(window):
                    add(
                        idx,
                        rule_id="WC-OWASP-009",
                        title="Security logging: access denial without visible log",
                        severity="LOW",
                        message=(
                            "Access appears denied without a nearby error_log / "
                            "wc_get_logger call, and no nonce/capability check was "
                            "found immediately above. Consider logging authz failures."
                        ),
                        owasp="A09:2025-Security Logging and Alerting Failures",
                        confidence=0.40,
                        source="access denial",
                        sink="wp_die/json_error",
                    )

        # ── A10:2025-Mishandling of Exceptional Conditions ────────────────
        if _EMPTY_CATCH.search(line):
            add(
                idx,
                rule_id="WC-OWASP-010",
                title="Empty or ignored catch block",
                severity="MEDIUM",
                message=(
                    "Exception is caught and ignored. Fail securely: log and "
                    "avoid continuing with invalid state."
                ),
                owasp="A10:2025-Mishandling of Exceptional Conditions",
                confidence=0.55,
                source="exception",
                sink="empty catch",
            )
        if _AT_SUPPRESSED.search(line):
            add(
                idx,
                rule_id="WC-OWASP-010",
                title="Error suppression (@) on sensitive call",
                severity="MEDIUM",
                message=(
                    "The @ operator suppresses errors on a sensitive operation. "
                    "Handle failures explicitly."
                ),
                owasp="A10:2025-Mishandling of Exceptional Conditions",
                confidence=0.60,
                source="code",
                sink="@-suppressed call",
            )
        if _DIE_RAW_INPUT.search(line):
            add(
                idx,
                rule_id="WC-OWASP-010",
                title="die/exit with raw user input",
                severity="MEDIUM",
                message=("die/exit uses raw user input. Use controlled error responses."),
                owasp="A10:2025-Mishandling of Exceptional Conditions",
                confidence=0.65,
                source="user input",
                sink="die/exit",
            )

    return findings
