from pathlib import Path

from scanner.deps import scan_composer, scan_dependencies


def test_missing_lock(tmp_path: Path):
    (tmp_path / "composer.json").write_text('{"name":"a/b","require":{}}')
    fs = scan_composer(tmp_path)
    assert any(f.rule_id == "WC-OWASP-003" for f in fs)


def test_scan_dependencies_empty(tmp_path: Path):
    assert isinstance(scan_dependencies(tmp_path), list)
