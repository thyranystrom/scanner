from pathlib import Path

from scanner import VERSION
from scanner.main import build_report, scan


def test_scan_returns_structured_report(tmp_path: Path):
    php = tmp_path / "example.php"
    php.write_text(
        "<?php\nadd_action('wp_ajax_nopriv_test', 'callback');\n",
        encoding="utf-8",
    )

    files, findings = scan(tmp_path)
    report = build_report(tmp_path, files, findings)

    assert report["scanner"]["version"] == VERSION  # not hardcoded
    assert report["summary"]["php_files_scanned"] == 1
    assert isinstance(report["findings"], list)
