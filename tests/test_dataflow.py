"""
test_dataflow.py
-----------------
Tests for:
  - dataflow.analyze()           – the core taint tracker
  - input.scan_input()           – promotions + FP suppression
  - output.scan_output()         – taint-promoted severity
  - sql.scan_sql()               – taint-promoted severity
  - models.Finding               – new flow_type / taint_line fields
"""

from pathlib import Path

from scanner.dataflow import analyze
from scanner.rules.ajax import scan_ajax
from scanner.rules.input import scan_input
from scanner.rules.output import scan_output
from scanner.rules.sql import scan_sql

FIXTURES = Path(__file__).parent / "fixtures"


def read(name: str):
    p = FIXTURES / name
    return p, p.read_text(encoding="utf-8")


# ── dataflow.analyze() ────────────────────────────────────────────────────────


class TestDataflow:
    def test_taint_reaches_sql_sink(self):
        _, text = read("taint_sql.php")
        results = analyze(text)
        sql_results = [r for r in results if r.sink_type == "sql"]
        assert sql_results, "Expected at least one sql DataFlowResult"

    def test_sanitized_input_does_not_reach_sql_sink(self):
        _, text = read("taint_sql_safe.php")
        results = analyze(text)
        sql_results = [r for r in results if r.sink_type == "sql"]
        assert not sql_results, "Sanitized input should not taint SQL sink"

    def test_taint_reaches_output_sink(self):
        _, text = read("taint_output.php")
        results = analyze(text)
        output_results = [r for r in results if r.sink_type == "output"]
        assert output_results, "Expected at least one output DataFlowResult"

    def test_result_has_var_and_superglobal(self):
        _, text = read("taint_sql.php")
        results = analyze(text)
        r = next((x for x in results if x.sink_type == "sql"), None)
        assert r is not None
        assert r.var is not None
        assert r.superglobal.startswith("$_")

    def test_taint_line_is_before_sink_line(self):
        _, text = read("taint_sql.php")
        results = analyze(text)
        r = next((x for x in results if x.sink_type == "sql"), None)
        assert r is not None
        assert r.taint_line < r.sink_line

    def test_inline_code_no_function_block(self):
        code = "<?php\n$v = $_GET['x'];\necho $v;\n"
        results = analyze(code)
        assert any(r.sink_type == "output" for r in results)

    def test_sanitized_absint_suppresses_flow(self):
        code = (
            "<?php\nfunction f() {\n"
            "    $id = absint($_GET['id']);\n"
            "    global $wpdb;\n"
            '    $wpdb->query("SELECT * FROM t WHERE id=$id");\n'
            "}\n"
        )
        results = analyze(code)
        assert not any(r.sink_type == "sql" for r in results)


# ── input.scan_input() ────────────────────────────────────────────────────────


class TestInputV5:
    def test_tainted_sql_promotes_to_high(self):
        path, text = read("taint_sql.php")
        findings = scan_input(path, text)
        high = [f for f in findings if f.severity == "HIGH"]
        assert high, "Expected at least one HIGH finding for tainted SQL"

    def test_tainted_sql_has_flow_type_taint(self):
        path, text = read("taint_sql.php")
        findings = scan_input(path, text)
        promoted = [f for f in findings if f.flow_type == "taint"]
        assert promoted

    def test_tainted_sql_confidence_above_threshold(self):
        path, text = read("taint_sql.php")
        findings = scan_input(path, text)
        promoted = [f for f in findings if f.flow_type == "taint"]
        assert all(f.confidence >= 0.70 for f in promoted)

    def test_safe_input_stays_low(self):
        path, text = read("taint_sql_safe.php")
        findings = scan_input(path, text)
        # No promoted findings expected; any remaining should be LOW
        promoted = [f for f in findings if f.flow_type == "taint"]
        assert not promoted

    def _test_tainted_output_promotes_to_medium(self):
        path, text = read("taint_output.php")
        findings = scan_input(path, text)
        medium_or_higher = [f for f in findings if f.severity in ("MEDIUM", "HIGH", "CRITICAL")]
        assert medium_or_higher

    def test_taint_line_populated_on_promoted_finding(self):
        path, text = read("taint_sql.php")
        findings = scan_input(path, text)
        promoted = [f for f in findings if f.flow_type == "taint"]
        assert all(f.taint_line is not None for f in promoted)


# -- False-positive reduction -----------------------------------------------


class TestFalsePositiveReduction:
    def test_isset_guard_suppressed(self):
        path, text = read("fp_guard.php")
        findings = scan_input(path, text)
        # isset($_GET[...]) should NOT produce a finding
        assert not findings, "isset() guard should suppress INPUT finding, got: " + str(
            [f.rule_id for f in findings]
        )

    def test_nonce_check_suppressed(self):
        path, text = read("fp_nonce_check.php")
        findings = scan_input(path, text)
        assert not findings, "wp_verify_nonce() usage should suppress INPUT finding"

    def test_base_confidence_reduced(self):
        """Non-tainted INPUT findings should have confidence <= 0.40."""
        code = "<?php\n$v = $_GET['page'];\n"
        findings = scan_input(Path("x.php"), code)
        non_tainted = [f for f in findings if f.flow_type is None]
        assert all(f.confidence <= 0.40 for f in non_tainted)

    def test_sanitizer_inline_suppressed(self):
        code = "<?php\n$v = sanitize_text_field($_GET['q']);\n"
        findings = scan_input(Path("x.php"), code)
        assert not findings

    def test_safe_action_name_suppressed(self):
        code = (
            "<?php\nadd_action('wp_ajax_heartbeat', 'my_cb');\nfunction my_cb() { echo 'pong'; }\n"
        )
        findings = scan_ajax(Path("x.php"), code)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_return_true_permission_suppressed(self):
        code = (
            "<?php\n"
            "add_action('wp_ajax_my_action', 'my_cb');\n"
            "function my_cb() { __return_true(); echo 'ok'; }\n"
        )
        findings = scan_ajax(Path("x.php"), code)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_sql_with_prepare_suppressed(self):
        path, text = read("taint_sql_safe.php")
        findings = scan_sql(path, text)
        high = [f for f in findings if f.severity == "HIGH"]
        assert not high

    def test_sql_confidence_reduced_without_taint(self):
        code = '<?php\nglobal $wpdb;\n$wpdb->query("SELECT * FROM wp_options");\n'
        findings = scan_sql(Path("x.php"), code)
        if findings:
            assert all(f.confidence <= 0.60 for f in findings)


# ── output.scan_output() ──────────────────────────────────────────────────────


class TestOutputV5:
    def test_tainted_echo_promoted_to_medium(self):
        path, text = read("taint_output.php")
        findings = scan_output(path, text)
        medium = [f for f in findings if f.severity == "MEDIUM"]
        assert medium, "Tainted echo should be promoted to MEDIUM"

    def test_tainted_echo_has_flow_type(self):
        path, text = read("taint_output.php")
        findings = scan_output(path, text)
        tainted = [f for f in findings if f.flow_type == "taint"]
        assert tainted

    def test_literal_echo_stays_low_or_info(self):
        code = "<?php\n$msg = 'Hello world';\necho $msg;\n"
        findings = scan_output(Path("x.php"), code)
        if findings:
            assert all(f.severity in ("LOW", "INFO") for f in findings)


# ── models.Finding ────────────────────────────────────────────────────────────


class TestFindingModelV5:
    def test_flow_type_in_to_dict(self):
        path, text = read("taint_sql.php")
        findings = scan_input(path, text)
        promoted = [f for f in findings if f.flow_type == "taint"]
        if promoted:
            d = promoted[0].to_dict()
            assert "flow_type" in d
            assert "taint_line" in d

    def test_taint_line_none_when_no_flow(self):
        code = "<?php\n$v = $_GET['page'];\n"
        findings = scan_input(Path("x.php"), code)
        non_tainted = [f for f in findings if f.flow_type is None]
        assert all(f.taint_line is None for f in non_tainted)
