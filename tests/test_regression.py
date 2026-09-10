"""Regression / ground-truth fixtures."""

from pathlib import Path

from scanner.rules.ajax import scan_ajax
from scanner.rules.output import scan_output

REG = Path(__file__).parent / "fixtures" / "regression"


def _read(name):
    p = REG / name
    return p, p.read_text(encoding="utf-8")


class TestRegressionMustFlag:
    def test_nopriv_update_is_high(self):
        path, text = _read("must_flag_nopriv_update.php")
        findings = scan_ajax(path, text)
        auth = [f for f in findings if f.rule_id == "WC-AUTH-001"]
        assert auth, "must flag public AJAX without auth writing options"
        assert auth[0].severity == "HIGH"
        assert auth[0].confidence >= 0.85


class TestRegressionMustNotFlag:
    def test_auth_in_helper(self):
        path, text = _read("must_not_flag_auth_helper.php")
        findings = scan_ajax(path, text)
        assert not any(f.rule_id == "WC-AUTH-001" for f in findings)

    def test_phpcs_echo(self):
        path, text = _read("must_not_flag_phpcs_echo.php")
        findings = scan_output(path, text)
        assert not any(f.rule_id == "WC-OUTPUT-001" for f in findings)
