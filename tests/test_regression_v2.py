"""
test_regression_v2.py
Regression tests based on real Klarna-plugin cases and edge cases.
Ensures no rule silently stops working after future updates.
"""

from pathlib import Path

from scanner.dataflow import analyze
from scanner.models import Finding
from scanner.rules.input import scan_input
from scanner.rules.output import scan_output
from scanner.rules.owasp_top10 import scan_owasp_top10
from scanner.rules.sql import scan_sql
from scanner.triage import AutoClassifier

FIXTURES = Path(__file__).parent / "fixtures" / "regression"


def read(name):
    p = FIXTURES / name
    return p, p.read_text(encoding="utf-8")


# -- Regression: FP suppression -------------------------------------------------


class TestFalsePositiveRegression:
    """Real cases from the Klarna plugin that previously produced false positives."""

    def test_wc_get_var_suppresses_input(self):
        """wc_get_var() is a WooCommerce sanitizer -- should not be flagged."""
        path, text = read("must_not_flag_wc_get_var.php")
        findings = scan_input(path, text)
        input_fp = [f for f in findings if "INPUT" in f.rule_id]
        assert not input_fp, f"wc_get_var() falsely flagged: {input_fp}"

    def test_base64_json_decode_suppresses_input(self):
        """base64_decode(json_decode($_GET)) is deliberate data consumption -- not an INPUT finding."""
        path, text = read("must_not_flag_base64_input.php")
        findings = scan_input(path, text)
        input_fp = [f for f in findings if "INPUT" in f.rule_id]
        assert not input_fp, f"base64 wrapper falsely flagged: {input_fp}"

    def test_hardcoded_s3_url_not_ssrf(self):
        """A hardcoded S3 URL in wp_remote_get should NOT be flagged as SSRF."""
        path, text = read("must_not_flag_hardcoded_s3_url.php")
        findings = scan_owasp_top10(path, text)
        ssrf = [f for f in findings if f.rule_id == "WC-OWASP-010"]
        assert not ssrf, f"Hardcoded S3 URL falsely flagged as SSRF: {ssrf}"

    def test_md5_cache_key_not_medium(self):
        """md5() used as a cache key (checksum context) should be LOW, not MEDIUM."""
        path, text = read("must_not_flag_md5_cache_key.php")
        findings = scan_owasp_top10(path, text)
        md5_f = [f for f in findings if f.rule_id == "WC-OWASP-002"]
        if md5_f:
            assert all(f.severity == "LOW" for f in md5_f), (
                f"md5 cache key should be LOW, got: {[f.severity for f in md5_f]}"
            )

    def test_phpcs_nopriv_no_flag(self):
        """wp_ajax_nopriv_heartbeat is a safe WordPress core hook -- should not be flagged."""
        path, text = read("must_not_flag_phpcs_echo.php")
        findings = scan_output(path, text)
        assert not any(f.rule_id == "WC-OUTPUT-001" for f in findings)


# -- Regression: TP requirements -------------------------------------------------


class TestTruePositiveRegression:
    """Real vulnerabilities that must always be flagged."""

    def test_taint_chain_sql_flagged(self):
        """A taint chain $_POST -> $raw -> $id -> SQL must produce WC-SQL-001."""
        path, text = read("must_flag_taint_chain_sql.php")
        findings = scan_sql(path, text)
        sql = [f for f in findings if f.rule_id == "WC-SQL-001"]
        assert sql, "Taint chain SQL injection not detected"

    def test_nopriv_ajax_update_flagged(self):
        """wp_ajax_nopriv_ that updates data without auth should be flagged."""
        path, text = read("must_flag_nopriv_update.php")
        from scanner.rules.ajax import scan_ajax

        findings = scan_ajax(path, text)
        assert any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_taint_chain_preserves_line(self):
        """taint_line must come BEFORE sink_line in chained analysis."""
        code = "<?php\n$a = $_POST['x'];\n$b = $a;\nglobal $wpdb;\n$wpdb->query(\"SELECT * WHERE id=$b\");\n"
        results = analyze(code)
        sql = [r for r in results if r.sink_type == "sql"]
        assert sql, "Taint chain not detected"
        assert sql[0].taint_line < sql[0].sink_line, (
            f"taint_line {sql[0].taint_line} should be before sink_line {sql[0].sink_line}"
        )


# ── AutoClassifier ────────────────────────────────────────────────────────────


class TestAutoClassifier:
    def _finding(self, **kw) -> Finding:
        d = {
            "rule_id": "WC-SQL-001",
            "severity": "HIGH",
            "title": "SQL Injection",
            "file": "src/handler.php",
            "line": 10,
            "message": "msg",
            "owasp": "A03",
            "confidence": 0.87,
            "source": "$_POST",
            "sink": "$wpdb->query()",
            "evidence": "  10:     $wpdb->query($id);",
        }
        d.update(kw)
        return Finding(**d)

    def test_taint_chain_classified_likely_tp(self):
        f = self._finding(flow_type="taint", taint_line=5, sink="$wpdb->query()")
        v = AutoClassifier.classify(f)
        assert v.label == "likely_tp"

    def test_very_low_confidence_classified_fp(self):
        f = self._finding(confidence=0.10)
        v = AutoClassifier.classify(f)
        assert v.label == "likely_fp"

    def test_test_path_classified_fp(self):
        f = self._finding(file="tests/fixtures/test_handler.php")
        v = AutoClassifier.classify(f)
        assert v.label == "likely_fp"

    def test_high_confidence_critical_likely_tp(self):
        f = self._finding(
            confidence=0.93,
            severity="CRITICAL",
            sink="unserialize()",
            evidence="  10: unserialize($_POST['x']);",
        )
        v = AutoClassifier.classify(f)
        assert v.label == "likely_tp"

    def test_filter_likely_fp_removes_test_paths(self):
        findings = [
            self._finding(file="tests/test_handler.php", confidence=0.85),
            self._finding(
                file="src/real_handler.php", confidence=0.85, flow_type="taint", taint_line=5
            ),
        ]
        kept, removed = AutoClassifier.filter_likely_fp(findings)
        assert len(kept) == 1
        assert len(removed) == 1
        assert "real_handler" in kept[0].file


# -- Fingerprint stability -------------------------------------------------------


class TestFingerprintStability:
    """Fingerprints should remain stable across line-number shifts."""

    def _finding(self, line, evidence) -> Finding:
        return Finding(
            rule_id="WC-SQL-001",
            severity="HIGH",
            title="SQL Injection",
            file="src/handler.php",
            line=line,
            message="msg",
            owasp="A05:2025-Injection",
            confidence=0.87,
            source="$_POST",
            sink="query()",
            evidence=evidence,
        )

    def test_fingerprint_stable_across_line_shift(self):
        """
        Identical code on line 10 vs line 15 should produce the SAME fingerprint
        when the evidence hash is correctly included.
        """
        ev_template = "  {line}:     $wpdb->query($id);"
        f10 = self._finding(10, ev_template.format(line=10))
        f15 = self._finding(15, ev_template.format(line=15))
        # With the code-node hash included, both should have the same fingerprint (the code is identical)
        assert f10.fingerprint() == f15.fingerprint(), (
            "Fingerprint should be stable across line shifts when code is identical"
        )

    def test_fingerprint_changes_when_code_changes(self):
        """Different code on the same line should produce DIFFERENT fingerprints."""
        f_vuln = self._finding(10, "  10:     $wpdb->query($id);")
        f_safe = self._finding(
            10, "  10:     $wpdb->query($wpdb->prepare('SELECT * WHERE id=%d', $id));"
        )
        assert f_vuln.fingerprint() != f_safe.fingerprint(), (
            "Fingerprint should change when code changes"
        )
