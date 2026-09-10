from scanner.models import Finding


def test_owasp_mapping():
    finding = Finding(
        rule_id="WC-OWASP-003",
        title="SQL Injection",
        file="woo-plugin.php",
        line=42,
        severity="HIGH",
        owasp="A05:2025-Injection",
        message="Unescaped SQL query detected.",
        confidence=0.9,
    )
    assert finding.owasp == "A05:2025-Injection"


def test_sarif_export(tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    p = d / "scan.sarif"

    finding = Finding(
        rule_id="WC-OWASP-001",
        title="Test Vuln",
        file="test.php",
        line=10,
        severity="MEDIUM",
        owasp="A01:2025-Broken Access Control",
        message="Test desc",
        confidence=0.9,
    )
    p.write_text(str(finding.to_dict()))
    assert p.exists()
