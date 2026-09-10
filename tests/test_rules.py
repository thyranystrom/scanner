"""
test_rules.py -- uses PHP fixtures rather than inline strings.

Each fixture is a small, purpose-built PHP file that documents:
  - what it tests
  - which rule IDs are expected to fire (or not fire)

This makes the tests self-documenting and easy to extend.
"""

from pathlib import Path

from scanner.rules.ajax import scan_ajax
from scanner.rules.auth import scan_rest_and_admin
from scanner.rules.input import scan_input
from scanner.rules.output import scan_output
from scanner.rules.sql import scan_sql

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> tuple[Path, str]:
    path = FIXTURES / name
    return path, path.read_text(encoding="utf-8")


# ── AJAX ──────────────────────────────────────────────────────────────────────


class TestAjax:
    def test_missing_auth_handler_detected(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_ajax(path, text)
        rule_ids = [f.rule_id for f in findings]
        assert "WC-AUTH-001" in rule_ids

    def test_safe_handler_not_detected(self):
        path, text = read_fixture("ajax_safe.php")
        findings = scan_ajax(path, text)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_nopriv_has_higher_confidence(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_ajax(path, text)
        auth_findings = [f for f in findings if f.rule_id == "WC-AUTH-001"]
        assert auth_findings, "Expected WC-AUTH-001 to be present"
        assert auth_findings[0].confidence >= 0.70

    def test_finding_has_source_and_sink(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_ajax(path, text)
        auth_findings = [f for f in findings if f.rule_id == "WC-AUTH-001"]
        assert auth_findings[0].source is not None
        assert auth_findings[0].sink is not None

    def test_inline_nonce_suppresses_finding(self):
        """Nonce check directly after add_action should suppress WC-AUTH-001."""
        code = "add_action('wp_ajax_demo', 'cb');\nfunction cb() { check_ajax_referer('demo'); }\n"
        findings = scan_ajax(Path("x.php"), code)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_capability_check_suppresses_finding(self):
        code = (
            "add_action('wp_ajax_demo', 'cb');\n"
            "function cb() { current_user_can('manage_options'); }\n"
        )
        findings = scan_ajax(Path("x.php"), code)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)


# ── REST / admin-post ─────────────────────────────────────────────────────────


class TestAuth:
    def test_rest_without_permission_callback_detected(self):
        path, text = read_fixture("rest_missing_permission_callback.php")
        findings = scan_rest_and_admin(path, text)
        assert any(f.rule_id == "WC-AUTH-002" for f in findings)

    def test_rest_with_permission_callback_not_detected(self):
        path, text = read_fixture("rest_safe.php")
        findings = scan_rest_and_admin(path, text)
        assert not any(f.rule_id == "WC-AUTH-002" for f in findings)

    def test_auth002_confidence(self):
        path, text = read_fixture("rest_missing_permission_callback.php")
        findings = scan_rest_and_admin(path, text)
        f = next(x for x in findings if x.rule_id == "WC-AUTH-002")
        assert f.confidence == 0.93

    def test_admin_post_without_auth_detected(self):
        code = "add_action('admin_post_demo', 'cb');\nfunction cb() { echo 'x'; }\n"
        findings = scan_rest_and_admin(Path("x.php"), code)
        assert any(f.rule_id == "WC-AUTH-003" for f in findings)

    def test_admin_post_with_nonce_not_detected(self):
        code = (
            "add_action('admin_post_demo', 'cb');\nfunction cb() { check_admin_referer('demo'); }\n"
        )
        findings = scan_rest_and_admin(Path("x.php"), code)
        assert not any(f.rule_id == "WC-AUTH-003" for f in findings)


# ── Input ─────────────────────────────────────────────────────────────────────


class TestInput:
    def test_raw_get_detected(self):
        code = "$v = $_GET['id'];\n"
        findings = scan_input(Path("x.php"), code)
        assert any(f.rule_id == "WC-INPUT-001" for f in findings)

    def test_raw_post_detected(self):
        code = "$v = $_POST['name'];\n"
        findings = scan_input(Path("x.php"), code)
        assert any(f.rule_id == "WC-INPUT-002" for f in findings)

    def test_raw_request_detected(self):
        code = "$v = $_REQUEST['q'];\n"
        findings = scan_input(Path("x.php"), code)
        assert any(f.rule_id == "WC-INPUT-003" for f in findings)

    def test_sanitize_text_field_suppresses(self):
        code = "$v = sanitize_text_field($_GET['id']);\n"
        findings = scan_input(Path("x.php"), code)
        assert not findings

    def test_absint_suppresses(self):
        code = "$v = absint($_POST['qty']);\n"
        findings = scan_input(Path("x.php"), code)
        assert not findings

    def test_intval_suppresses(self):
        code = "$v = intval($_GET['page']);\n"
        findings = scan_input(Path("x.php"), code)
        assert not findings

    def test_wc_clean_suppresses(self):
        code = "$v = wc_clean($_POST['value']);\n"
        findings = scan_input(Path("x.php"), code)
        assert not findings

    def test_finding_has_source(self):
        code = "$v = $_POST['name'];\n"
        findings = scan_input(Path("x.php"), code)
        f = next(x for x in findings if x.rule_id == "WC-INPUT-002")
        assert f.source == "$_POST"

    def test_missing_auth_ajax_fixture_has_post(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_input(path, text)
        assert any(f.rule_id == "WC-INPUT-002" for f in findings)

    def test_safe_ajax_fixture_has_no_input_finding(self):
        path, text = read_fixture("ajax_safe.php")
        findings = scan_input(path, text)
        assert not any(
            f.rule_id in ("WC-INPUT-001", "WC-INPUT-002", "WC-INPUT-003") for f in findings
        )


# ── Output ────────────────────────────────────────────────────────────────────


class TestOutput:
    def test_bare_echo_detected(self):
        code = "echo $value;\n"
        findings = scan_output(Path("x.php"), code)
        assert any(f.rule_id == "WC-OUTPUT-001" for f in findings)

    def test_esc_html_not_detected(self):
        code = "echo esc_html($value);\n"
        findings = scan_output(Path("x.php"), code)
        assert not any(f.rule_id == "WC-OUTPUT-001" for f in findings)

    def test_finding_has_sink(self):
        code = "echo $value;\n"
        findings = scan_output(Path("x.php"), code)
        f = next(x for x in findings if x.rule_id == "WC-OUTPUT-001")
        assert f.sink == "echo"

    def test_missing_auth_ajax_fixture_has_output_finding(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_output(path, text)
        assert any(f.rule_id == "WC-OUTPUT-001" for f in findings)


# ── SQL ───────────────────────────────────────────────────────────────────────


class TestSql:
    def test_tainted_query_without_prepare_detected(self):
        # Only fires when a tainted variable demonstrably reaches a sink
        path, text = read_fixture("sql_missing_prepare.php")
        findings = scan_sql(path, text)
        assert any(f.rule_id == "WC-SQL-001" for f in findings)

    def test_query_with_prepare_not_detected(self):
        path, text = read_fixture("sql_safe.php")
        findings = scan_sql(path, text)
        assert not any(f.rule_id == "WC-SQL-001" for f in findings)

    def test_finding_has_source_and_sink(self):
        path, text = read_fixture("sql_missing_prepare.php")
        findings = scan_sql(path, text)
        f = next(x for x in findings if x.rule_id == "WC-SQL-001")
        assert f.source is not None
        assert f.sink is not None

    def test_tainted_get_results_detected(self):
        # Tainted variable must reach the sink
        code = (
            "function f() {\n"
            "    global $wpdb;\n"
            "    $id = $_GET['id'];\n"
            '    $wpdb->get_results("SELECT * FROM t WHERE id=$id");\n'
            "}\n"
        )
        findings = scan_sql(Path("x.php"), code)
        assert any(f.rule_id == "WC-SQL-001" for f in findings)


# ── Finding model ─────────────────────────────────────────────────────────────


class TestFindingModel:
    def test_to_dict_includes_source_and_sink(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_ajax(path, text)
        d = findings[0].to_dict()
        assert "source" in d
        assert "sink" in d

    def test_to_dict_includes_evidence(self):
        path, text = read_fixture("ajax_missing_auth.php")
        findings = scan_ajax(path, text)
        d = findings[0].to_dict()
        assert "evidence" in d
        assert d["evidence"] is not None
