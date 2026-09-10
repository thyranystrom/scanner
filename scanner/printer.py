"""
printer.py
----------
Terminal output renderer: prints scan results with an inline fix suggestion
attached to every finding, unconditionally.

Design choices:
  - Every finding always shows a fix suggestion directly under its evidence
    block. No flag is required to *see* the suggestion.
  - The line that needs to change is shown in red, prefixed with ✗ BEFORE:
  - The suggested replacement line is shown in green, prefixed with ✓ AFTER:
  - When no automated code fix exists for a rule, a short text remediation
    tip is shown instead.
  - --fix-apply remains the only way to actually WRITE changes to disk.
"""

from __future__ import annotations

import sys
from typing import Any

from .utils import format_owasp

# ── ANSI ──────────────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_ITALIC = "\033[3m"
_BG_RED = "\033[41m"
_BG_GRN = "\033[42m"
_BG_YEL = "\033[43m"
_BG_DARK = "\033[100m"  # dark grey background for code blocks

_RED = "\033[91m"
_ORANGE = "\033[33m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_BLUE = "\033[94m"
_GREY = "\033[90m"
_WHITE = "\033[97m"
_MAGENTA = "\033[95m"

_SEV_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": (_RED, "✖"),
    "HIGH": (_RED, "✖"),
    "MEDIUM": (_ORANGE, "⚠"),
    "LOW": (_YELLOW, "–"),
    "INFO": (_CYAN, "·"),
}

# Fallback remediation tips (used when no CodeFix strategy covers the rule)
_REMEDIATION: dict[str, str] = {
    "WC-SECRET-001": "Move credentials to WooCommerce settings: $this->get_option('api_key')",
    "WC-SQL-001": "Use $wpdb->prepare(): $wpdb->query( $wpdb->prepare( 'SELECT … WHERE id=%d', $id ) )",
    "WC-XSS-001": "Escape before output: echo esc_html( $var );",
    "WC-OUTPUT-001": "Escape before output: echo esc_html( $var );",
    "WC-INPUT-001": "Sanitize: $val = sanitize_text_field( $_GET['key'] );",
    "WC-INPUT-002": "Sanitize: $val = sanitize_text_field( $_POST['key'] );",
    "WC-INPUT-003": "Sanitize: $val = sanitize_text_field( $_REQUEST['key'] );",
    "WC-AUTH-001": "Add at top of handler: check_ajax_referer( 'action', '_wpnonce' );",
    "WC-AUTH-002": "Add permission_callback: 'permission_callback' => fn() => current_user_can('manage_options')",
    "WC-AUTH-003": "Add: if ( ! check_admin_referer( 'action' ) ) { wp_die(); }",
    "WC-OWASP-002": "Do not force WP_DEBUG/phpinfo in plugin code; keep debug only in non-prod wp-config.",
    "WC-OWASP-002B": "Remove phpinfo() from production paths; it leaks server configuration.",
    "WC-OWASP-004": "Passwords: wp_hash_password(). Checksums/cache keys: hash('sha256', …) optional.",
    "WC-OWASP-001": "Do not pass user-controlled URLs to wp_remote_*; allowlist hosts/schemes.",
    "WC-OWASP-008": "Replace unserialize: json_decode( $raw, true )",
    "WC-DANGER-001": "Remove eval/exec/shell_exec. If unavoidable, whitelist args strictly.",
    # NOTE: the six entries below were missing entirely -- every rule ID
    # not present here AND not covered by an automated CodeFix strategy
    # (see autofix.py's _REGISTRY) silently prints no remediation guidance
    # at all, breaking this module's own stated design principle that
    # every finding always shows a fix suggestion. These correspond to
    # the OWASP Top 10:2025 categories added when owasp_top10.py was
    # extended to cover all ten categories.
    "WC-SECRET-002": "Move credentials to WooCommerce settings: $this->get_option('api_key')",
    "WC-OWASP-003": "Run `composer update && composer install --no-dev` to regenerate "
    "composer.lock, and run `composer audit` in CI to catch dependencies with known issues.",
    "WC-OWASP-005": "Never pass $_GET/$_POST directly to include/require; validate "
    "against a strict allowlist of known file names first.",
    "WC-OWASP-006": "Remove hard-coded auth/nonce/CSRF bypass flags before release; "
    "resolve security-related TODO/FIXME comments before shipping.",
    "WC-OWASP-007": "Use wp_check_password() or password_verify() instead of "
    "comparing passwords with ==/===.",
    "WC-OWASP-009": "Log authorization failures before denying access: "
    "wc_get_logger()->warning( ... ) before wp_die() / wp_send_json_error().",
    "WC-OWASP-010": "Handle exceptions explicitly -- log the error and fail safely "
    "instead of an empty catch block, an @-suppressed call, or raw input in die()/exit().",
}


def _tip(rule_id: str) -> str | None:
    if not rule_id:
        return None
    return _REMEDIATION.get(rule_id)


def write_markdown_report(findings: list[dict[str, Any]], output_path: str) -> None:
    md = ["# 🛡️ WooCommerce Security Scan Report\n"]
    if not findings:
        md.append("✅ **No security issues found.**\n")
    else:
        md.append(f"**{len(findings)} finding(s)**\n")
        md.append("| Severity | Rule | Location | Title | Fix suggestion |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            loc = f"`{f.get('file', '')}:{f.get('line', '')}`"
            tip = _tip(f.get("rule_id", "")) or f.get("message", "").replace("\n", " ")
            md.append(
                f"| **{f.get('severity', '')}** | `{f.get('rule_id', '')}` "
                f"| {loc} | {f.get('title', '')} | {tip} |"
            )
        md.append("\n---\n")
        md.append("### Fix suggestions per finding\n")
        for i, f in enumerate(findings, 1):
            fix = f.get("autofix")
            md.append(f"**#{i} {f.get('rule_id', '')}** `{f.get('file', '')}:{f.get('line', '')}`")
            if fix:
                md.append(f"```diff\n{fix.get('diff', '')}\n```")
            else:
                md.append(f"> {_tip(f.get('rule_id', '')) or f.get('message', '')}\n")
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))


class Printer:
    """
    All terminal output.
    colour=True  → full ANSI
    colour=False → plain text (auto when not a TTY or --no-color)
    """

    def __init__(self, colour: bool | None = None):
        if colour is None:
            colour = sys.stdout.isatty()
        self._c_on = colour

    # ── primitives ────────────────────────────────────────────────────────────

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self._c_on else text

    def _bold(self, t: str) -> str:
        return self._c(_BOLD, t)

    def _dim(self, t: str) -> str:
        return self._c(_DIM, t)

    def _col(self, colour: str, t: str) -> str:
        return self._c(colour, t)

    def _rule(self, char: str = "─", width: int = 72) -> str:
        return self._dim(char * width)

    def _sev_badge(self, severity: str) -> str:
        colour, icon = _SEV_STYLE.get(severity, (_GREY, "?"))
        return self._c(_BOLD + colour, f" {icon} {severity:<8}")

    # ── public ────────────────────────────────────────────────────────────────

    def banner(self, version: str) -> None:
        w = 72
        print(self._dim("╔" + "═" * (w - 2) + "╗"))
        print(
            self._dim("║ ")
            + self._c(_BOLD + _CYAN, "WooCommerce Security Scanner")
            + "  "
            + self._c(_BOLD + _WHITE, f"v{version}")
            + self._dim(" " * (w - 36) + "║")
        )
        print(self._dim("╚" + "═" * (w - 2) + "╝"))

    def summary(self, target, files_scanned, total_findings, counts) -> None:
        print()
        print(self._bold("  Target   ") + self._col(_WHITE, str(target)))
        print(self._bold("  Scanned  ") + f"{files_scanned} PHP files")
        print(self._bold("  Findings ") + self._fmt_count(total_findings))
        if counts:
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                n = counts.get(sev)
                if n:
                    colour, _ = _SEV_STYLE.get(sev, (_GREY, ""))
                    parts.append(self._c(colour, f"{n} {sev}"))
            print("            " + "  ".join(parts))
        print()
        print(self._rule())

    def _fmt_count(self, n: int) -> str:
        if n == 0:
            return self._c(_GREEN, "0  ✓ Clean")
        colour = _RED if n >= 5 else _ORANGE if n >= 2 else _YELLOW
        return self._c(colour, str(n))

    def findings_header(self) -> None:
        print(self._bold("\n  Findings\n"))

    def no_findings(self) -> None:
        print("  " + self._c(_GREEN + _BOLD, "✓") + "  No findings.")
        print()

    def json_written(self, path: str) -> None:
        print("\n  " + self._dim("JSON →") + "  " + self._col(_WHITE, path))

    # ── core finding block ────────────────────────────────────────────────────

    def finding(self, f: dict[str, Any], index: int, fix=None) -> None:
        """
        Print one finding.  `fix` is an optional CodeFix object; if supplied
        it is rendered inline.  If absent, a text remediation tip is shown.
        """
        sev = f["severity"]
        rule_id = f["rule_id"]
        filepath = f["file"]
        line = f["line"]
        title = f["title"]
        conf = f["confidence"]
        source = f.get("source") or ""
        sink = f.get("sink") or ""
        flow = f.get("flow_type")
        taint_ln = f.get("taint_line")
        evidence = f.get("evidence") or ""
        message = f.get("message") or ""

        colour, icon = _SEV_STYLE.get(sev, (_GREY, "?"))

        # ── header ──────────────────────────────────────────────────────────
        num = self._dim(f"#{index:02d}")
        badge = self._sev_badge(sev)
        is_owasp_rule = str(rule_id).startswith("WC-OWASP")
        primary = format_owasp(f.get("owasp")) if is_owasp_rule else title
        primary_disp = self._c(_BOLD + _BLUE, primary)
        conf_str = self._dim(f"conf {conf:.0%}")
        print(f"  {num} {badge}  {primary_disp}  {conf_str}")

        # ── location ────────────────────────────────────────────────────────
        loc = self._c(_BOLD + _WHITE, f"{filepath}:{line}")
        print(f"       {self._dim('at')} {loc}")

        if is_owasp_rule:
            print(f"       {self._c(colour, title)}")
            print(f"       {self._dim('rule')} {self._dim(rule_id)}")
        else:
            print(f"       {self._dim('rule')} {self._dim(rule_id)}")

        # ── taint tag ───────────────────────────────────────────────────────
        if flow == "taint" and taint_ln:
            print(f"       {self._c(_BOLD + _RED, f'⇒ tainted from line {taint_ln}')}")

        # ── source / sink ───────────────────────────────────────────────────
        if source or sink:
            parts = []
            if source:
                parts.append(self._dim("source: ") + self._c(_CYAN, source))
            if sink:
                parts.append(self._dim("sink: ") + self._c(_ORANGE, sink))
            print("       " + "   ".join(parts))

        # ── evidence (syntax-highlighted lines) ──────────────────────────────
        if evidence:
            print(f"       {self._dim('┄' * 50)}")
            ev_lines = evidence.splitlines()
            cur_line = int(line)
            # Estimate which line in the snippet is the culprit
            for ev in ev_lines:
                # Evidence lines look like "  5:  code here"
                import re as _re

                m = _re.match(r"\s*(\d+):\s?(.*)", ev)
                if m and int(m.group(1)) == cur_line:
                    # Highlight the culprit line
                    num_part = self._c(_BOLD + _RED, f"  {m.group(1)}:")
                    code_part = self._c(_BOLD + _WHITE, m.group(2))
                    arrow = self._c(_RED, "◀")
                    print(f"       {num_part} {code_part}  {arrow}")
                else:
                    print("       " + self._dim(ev))
            print(f"       {self._dim('┄' * 50)}")

        # ── message ─────────────────────────────────────────────────────────
        if message:
            print(f"       {self._dim('↳')} {self._dim(message)}")

        # ── FIX BLOCK ────────────────────────────────────────────────────────
        self._fix_block(rule_id, fix)

        print(self._rule())

    def _fix_block(self, rule_id: str, fix=None) -> None:
        """
        Always render a fix block.
        - If a CodeFix is supplied: show coloured before/after lines.
        - Otherwise: show a text remediation tip.
        """
        if fix is not None:
            # Coloured diff
            auto = fix.confidence >= 0.90
            label = (
                self._c(_BOLD + _GREEN, "✓ SUGGESTED FIX  (auto-applicable)")
                if auto
                else self._c(_BOLD + _YELLOW, "⚠ SUGGESTED FIX  (review before applying)")
            )
            print(f"\n       {label}")

            # BEFORE line – red background strip
            before = fix.original_line.strip()
            after = fix.fixed_line.strip()

            print(f"       {self._c(_DIM, 'BEFORE')}  {self._c(_RED + _BOLD, before)}")
            print(f"       {self._c(_DIM, 'AFTER ')}  {self._c(_GREEN + _BOLD, after)}")

            if fix.references:
                print(f"       {self._dim('docs →')} {self._dim(fix.references[0])}")
            print()

        else:
            # Fallback text tip
            tip = _tip(rule_id)
            if tip:
                label = self._c(_BOLD + _YELLOW, "💡 HOW TO FIX")
                print(f"\n       {label}")
                print(f"       {self._c(_GREEN, tip)}")
                print()

    # ── autofix summary (called after all findings, for --fix-apply) ──────────

    def autofix_summary(self, fixes: list) -> None:
        """Print a compact summary table of all fixes after the findings list."""
        if not fixes:
            return
        auto = [f for f in fixes if f.confidence >= 0.90]
        review = [f for f in fixes if f.confidence < 0.90]
        print()
        print(self._rule("═"))
        print(
            "  "
            + self._c(_BOLD + _GREEN, "AUTOFIX SUMMARY")
            + self._dim(
                f"   {len(fixes)} suggestion(s)"
                f"  ·  {len(auto)} auto-applicable"
                f"  ·  {len(review)} need review"
            )
        )
        print(self._rule("═"))
        for fix in fixes:
            tag = self._c(_GREEN + _BOLD, "✓") if fix.confidence >= 0.90 else self._c(_YELLOW, "⚠")
            loc = self._c(_WHITE, f"{fix.file}:{fix.line}")
            rid = self._c(_BLUE, fix.rule_id)
            conf = self._dim(f"{fix.confidence:.0%}")
            print(f"  {tag}  {rid:<18} {loc:<45} {conf}")
        print()
        print(
            self._dim("  Run with ")
            + self._c(_BOLD + _CYAN, "--fix-apply")
            + self._dim(f" to write the {len(auto)} high-confidence fix(es) to disk.")
        )
        print()

    def autofix_header(self, total: int, auto: int) -> None:
        # kept for backward compat; now a no-op (fixes shown inline)
        pass

    def autofix_entry(self, fix) -> None:
        # kept for backward compat; now a no-op (fixes shown inline)
        pass

    def triage_banner(self, lines) -> None:
        print()
        print("─" * 72)
        print("  MANUAL REVIEW (HIGH / CRITICAL)")
        print("─" * 72)
        for line in lines:
            print(f"  {line}" if line else "")
