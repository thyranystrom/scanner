"""Cross-file project index tests."""

from pathlib import Path

from scanner.deep import expand_chain, index_file
from scanner.project import build_project_index


def test_expand_cross_file(tmp_path: Path):
    a = tmp_path / "A.php"
    b = tmp_path / "B.php"
    a.write_text("<?php\nclass A {\n public function handler() { $this->guard(); }\n}\n")
    b.write_text("<?php\nclass B {\n public function guard() { check_ajax_referer('x'); }\n}\n")
    project = build_project_index(tmp_path)
    assert project.lookup("guard") is not None
    assert project.lookup("handler") is not None
    fidx = index_file(a.read_text(), file="A.php")
    chain = expand_chain("handler", fidx, project=project, max_hops=2)
    assert chain.has_auth
    assert chain.cross_file
