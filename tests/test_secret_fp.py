from pathlib import Path

from scanner.deps import scan_secrets_files


def test_option_key_not_secret(tmp_path: Path):
    (tmp_path / "a.php").write_text('$shared_secret_key = "{$prefix}shared_secret_{$key}";\n')
    assert scan_secrets_files(tmp_path) == []
