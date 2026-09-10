"""
test_autofix.py
Tests FixEngine, CodeFix, apply_fixes against every strategy.
"""

from __future__ import annotations

from scanner.autofix import CodeFix, FixEngine, apply_fixes
from scanner.models import Finding

engine = FixEngine()


def _f(**kw) -> Finding:
    d = {
        "rule_id": "WC-INPUT-002",
        "severity": "LOW",
        "title": "T",
        "file": "x.php",
        "line": 1,
        "message": "m",
        "owasp": "A03",
        "confidence": 0.35,
        "source": "$_POST",
        "sink": None,
    }
    d.update(kw)
    return Finding(**d)


# ── WC-INPUT sanitizer ────────────────────────────────────────────────────────


class TestInputFix:
    def test_text_key_gets_sanitize_text_field(self):
        f = _f(rule_id="WC-INPUT-002", line=1)
        fixes = engine.suggest([f], "$name = $_POST['name'];\n")
        assert fixes and "sanitize_text_field" in fixes[0].fixed_line

    def test_numeric_key_gets_absint(self):
        f = _f(rule_id="WC-INPUT-001", line=1)
        fixes = engine.suggest([f], "$id = $_GET['order_id'];\n")
        assert fixes and "absint" in fixes[0].fixed_line

    def test_email_key_gets_sanitize_email(self):
        f = _f(rule_id="WC-INPUT-002", line=1)
        fixes = engine.suggest([f], "$em = $_POST['email'];\n")
        assert fixes and "sanitize_email" in fixes[0].fixed_line

    def test_already_sanitized_produces_no_fix(self):
        f = _f(rule_id="WC-INPUT-002", line=1)
        fixes = engine.suggest([f], "$name = sanitize_text_field($_POST['name']);\n")
        assert not fixes

    def test_confidence_high_enough(self):
        f = _f(rule_id="WC-INPUT-002", line=1)
        fixes = engine.suggest([f], "$v = $_POST['x'];\n")
        assert fixes[0].confidence >= 0.88

    def test_has_wp_reference(self):
        f = _f(rule_id="WC-INPUT-001", line=1)
        fixes = engine.suggest([f], "$v = $_GET['q'];\n")
        assert any("developer.wordpress.org" in r for r in fixes[0].references)


# ── WC-SQL-001 prepare ────────────────────────────────────────────────────────


class TestSqlFix:
    def test_wraps_interpolated_query(self):
        f = _f(rule_id="WC-SQL-001", severity="HIGH", line=1)
        fixes = engine.suggest([f], '$wpdb->query("SELECT * FROM t WHERE id=$id");\n')
        assert fixes and "prepare" in fixes[0].fixed_line

    def test_numeric_var_gets_percent_d(self):
        f = _f(rule_id="WC-SQL-001", severity="HIGH", line=1)
        fixes = engine.suggest([f], '$wpdb->get_row("SELECT * FROM t WHERE order_id=$order_id");\n')
        assert fixes and "%d" in fixes[0].fixed_line

    def test_text_var_gets_percent_s(self):
        f = _f(rule_id="WC-SQL-001", severity="HIGH", line=1)
        fixes = engine.suggest([f], "$wpdb->query(\"SELECT * FROM t WHERE email='$email'\");\n")
        assert fixes and "%s" in fixes[0].fixed_line

    def test_confidence_below_auto_apply(self):
        f = _f(rule_id="WC-SQL-001", severity="HIGH", line=1)
        fixes = engine.suggest([f], '$wpdb->query("SELECT * FROM t WHERE x=$val");\n')
        assert fixes and fixes[0].confidence < 0.90

    def test_no_fix_without_variables(self):
        f = _f(rule_id="WC-SQL-001", severity="HIGH", line=1)
        fixes = engine.suggest([f], '$wpdb->query("SELECT * FROM t WHERE id=1");\n')
        assert not fixes


# ── WC-OUTPUT-001 / WC-XSS-001 ───────────────────────────────────────────────


class TestOutputFix:
    def test_bare_echo_wrapped(self):
        f = _f(rule_id="WC-OUTPUT-001", line=1)
        fixes = engine.suggest([f], "echo $value;\n")
        assert fixes and "esc_html" in fixes[0].fixed_line

    def test_xss_sink_wrapped(self):
        f = _f(rule_id="WC-XSS-001", line=1)
        fixes = engine.suggest([f], "echo $name;\n")
        assert fixes and "esc_html" in fixes[0].fixed_line

    def test_print_replaced_with_esc_echo(self):
        f = _f(rule_id="WC-OUTPUT-001", line=1)
        fixes = engine.suggest([f], "print($msg);\n")
        assert fixes and "esc_html" in fixes[0].fixed_line

    def test_interpolated_string_broken_into_parts(self):
        f = _f(rule_id="WC-OUTPUT-001", line=1)
        fixes = engine.suggest([f], 'echo "Hello $name!";\n')
        assert fixes and "esc_html" in fixes[0].fixed_line

    def test_already_escaped_no_fix(self):
        f = _f(rule_id="WC-OUTPUT-001", line=1)
        fixes = engine.suggest([f], "echo esc_html( $value );\n")
        assert not fixes

    def test_confidence_above_09_for_bare_echo(self):
        f = _f(rule_id="WC-OUTPUT-001", line=1)
        fixes = engine.suggest([f], "echo $v;\n")
        assert fixes[0].confidence >= 0.90


# ── WC-SECRET-001 ────────────────────────────────────────────────────────────


class TestSecretFix:
    def test_replaces_with_get_option(self):
        f = _f(rule_id="WC-SECRET-001", line=1)
        fixes = engine.suggest([f], '$api_key = "sk_live_abcdefghijklmnopqrstuvwx";\n')
        assert fixes and "get_option" in fixes[0].fixed_line

    def test_option_key_derived_from_varname(self):
        f = _f(rule_id="WC-SECRET-001", line=1)
        fixes = engine.suggest([f], '$stripe_secret = "sk_live_abcdefghijklmnopqrstuvwx";\n')
        assert fixes and "stripe_secret" in fixes[0].fixed_line

    def test_confidence_requires_manual_review(self):
        f = _f(rule_id="WC-SECRET-001", line=1)
        fixes = engine.suggest([f], '$pw = "supersecret123456789012";\n')
        assert fixes and fixes[0].confidence < 0.90


# ── WC-OWASP-004 ─────────────────────────────────────────────────────────────


class TestWeakCryptoFix:
    def test_md5_replaced_with_sha256(self):
        f = _f(rule_id="WC-OWASP-004", line=1)
        fixes = engine.suggest([f], "$hash = md5($data);\n")
        assert fixes and "sha256" in fixes[0].fixed_line

    def test_sha1_replaced_with_sha256(self):
        f = _f(rule_id="WC-OWASP-004", line=1)
        fixes = engine.suggest([f], "$h = sha1($token);\n")
        assert fixes and "sha256" in fixes[0].fixed_line

    def test_password_context_uses_wp_hash(self):
        f = _f(rule_id="WC-OWASP-004", line=1)
        fixes = engine.suggest([f], "$hashed = md5($password);\n")
        assert fixes and "wp_hash_password" in fixes[0].fixed_line


# ── WC-OWASP-008 ─────────────────────────────────────────────────────────────


class TestUnserializeFix:
    def test_replaced_with_json_decode(self):
        f = _f(rule_id="WC-OWASP-008", line=1)
        fixes = engine.suggest([f], "$data = unserialize($raw);\n")
        assert fixes and "json_decode" in fixes[0].fixed_line

    def test_argument_preserved(self):
        f = _f(rule_id="WC-OWASP-008", line=1)
        fixes = engine.suggest([f], "$obj = unserialize($stored_value);\n")
        assert fixes and "$stored_value" in fixes[0].fixed_line


# ── CodeFix datatype ─────────────────────────────────────────────────────────


class TestCodeFix:
    def test_to_dict_has_required_keys(self):
        fix = CodeFix(
            rule_id="WC-INPUT-002",
            file="x.php",
            line=3,
            original_line='$v = $_POST["x"];',
            fixed_line='$v = sanitize_text_field( $_POST["x"] );',
            description="wrap",
            confidence=0.92,
        )
        d = fix.to_dict()
        for k in (
            "rule_id",
            "file",
            "line",
            "original",
            "fixed",
            "description",
            "confidence",
            "diff",
            "references",
            "auto_apply",
        ):
            assert k in d, f"Missing: {k}"

    def test_auto_apply_true_high_confidence(self):
        fix = CodeFix(
            rule_id="WC-INPUT-001",
            file="x.php",
            line=1,
            original_line="$v = $_GET['id'];",
            fixed_line="$v = absint( $_GET['id'] );",
            description="absint",
            confidence=0.93,
        )
        assert fix.to_dict()["auto_apply"] is True

    def test_auto_apply_false_low_confidence(self):
        fix = CodeFix(
            rule_id="WC-SQL-001",
            file="x.php",
            line=1,
            original_line='$wpdb->query("...$v...");',
            fixed_line='$wpdb->query($wpdb->prepare("...%s...", $v));',
            description="prepare",
            confidence=0.82,
        )
        assert fix.to_dict()["auto_apply"] is False

    def test_diff_auto_generated(self):
        fix = CodeFix(
            rule_id="WC-INPUT-002",
            file="f.php",
            line=5,
            original_line="$n = $_POST['name'];",
            fixed_line="$n = sanitize_text_field( $_POST['name'] );",
            description="fix",
            confidence=0.89,
        )
        assert "---" in fix.diff and "+++" in fix.diff
        assert "-$n = $_POST" in fix.diff


# ── apply_fixes ───────────────────────────────────────────────────────────────


class TestApplyFixes:
    def test_single_fix_applied(self):
        src = "$name = $_POST['name'];\necho $name;\n"
        fixes = [
            CodeFix(
                rule_id="WC-INPUT-002",
                file="x.php",
                line=1,
                original_line="$name = $_POST['name'];",
                fixed_line="$name = sanitize_text_field( $_POST['name'] );",
                description="fix",
                confidence=0.92,
            )
        ]
        result = apply_fixes(src, fixes)
        assert "sanitize_text_field" in result
        assert "echo $name;" in result

    def test_two_fixes_different_lines(self):
        src = "$id = $_GET['id'];\necho $id;\n"
        fixes = [
            CodeFix(
                rule_id="WC-INPUT-001",
                file="x.php",
                line=1,
                original_line="$id = $_GET['id'];",
                fixed_line="$id = absint( $_GET['id'] );",
                description="fix1",
                confidence=0.93,
            ),
            CodeFix(
                rule_id="WC-OUTPUT-001",
                file="x.php",
                line=2,
                original_line="echo $id;",
                fixed_line="echo esc_html( $id );",
                description="fix2",
                confidence=0.93,
            ),
        ]
        result = apply_fixes(src, fixes)
        assert "absint" in result and "esc_html" in result

    def test_stale_original_skipped(self):
        src = "$id = absint($_GET['id']);\n"
        fixes = [
            CodeFix(
                rule_id="WC-INPUT-001",
                file="x.php",
                line=1,
                original_line="$id = $_GET['id'];",  # stale
                fixed_line="$id = absint( $_GET['id'] );",
                description="fix",
                confidence=0.93,
            )
        ]
        assert apply_fixes(src, fixes) == src

    def test_first_fix_wins_on_same_line(self):
        src = "$v = $_POST['x'];\n"
        fixes = [
            CodeFix(
                rule_id="WC-INPUT-002",
                file="x.php",
                line=1,
                original_line="$v = $_POST['x'];",
                fixed_line="$v = sanitize_text_field( $_POST['x'] );",
                description="fix1",
                confidence=0.92,
            ),
            CodeFix(
                rule_id="WC-INPUT-002",
                file="x.php",
                line=1,
                original_line="$v = $_POST['x'];",
                fixed_line="$v = absint( $_POST['x'] );",
                description="fix2",
                confidence=0.91,
            ),
        ]
        result = apply_fixes(src, fixes)
        assert result.count("$_POST") == 1


# ── Integration ───────────────────────────────────────────────────────────────


class TestIntegration:
    def test_realistic_handler_three_findings(self):
        code = (
            "function handle() {\n"
            "    $id = $_POST['order_id'];\n"
            '    $wpdb->query("SELECT * FROM orders WHERE id=$id");\n'
            "    echo $id;\n"
            "}\n"
        )
        findings = [
            _f(rule_id="WC-INPUT-002", line=2),
            _f(rule_id="WC-SQL-001", line=3, severity="HIGH"),
            _f(rule_id="WC-OUTPUT-001", line=4),
        ]
        fixes = engine.suggest(findings, code)
        rule_ids = {f.rule_id for f in fixes}
        assert {"WC-INPUT-002", "WC-SQL-001", "WC-OUTPUT-001"} == rule_ids
        assert len(fixes) == 3

    def test_one_fix_per_line(self):
        code = "$v = $_POST['x'];\n"
        findings = [
            _f(rule_id="WC-INPUT-002", line=1),
            _f(rule_id="WC-XSS-001", line=1),
        ]
        fixes = engine.suggest(findings, code)
        assert len(fixes) == 1
