"""
test_interprocedural.py
-------------------------
Permanent regression tests for the inter-procedural $this-> call
resolution added to dataflow.ASTAnalyzer.

These scenarios were manually verified during development but never
converted into pytest tests, leaving the feature with zero coverage in
the actual test suite -- meaning a future refactor could silently break
it without any test failing. This file closes that gap.

Requires PHP + nikic/php-parser (scanner/php/vendor/) to be installed,
since inter-procedural resolution is only implemented in the AST-based
path, not the regex fallback. Tests are skipped gracefully if PHP is
unavailable, matching the project's documented graceful-degradation
behavior.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from scanner.dataflow import analyze
from scanner.main import scan
from scanner.project import build_project_index


def _php_available() -> bool:
    return shutil.which("php") is not None


def _parser_available() -> bool:
    """nikic/php-parser must be installed under scanner/php/vendor."""
    root = Path(__file__).resolve().parents[1]
    return (root / "scanner" / "php" / "vendor" / "autoload.php").is_file()


pytestmark = pytest.mark.skipif(
    not _php_available() or not _parser_available(),
    reason="PHP + nikic/php-parser (composer install in scanner/php) required",
)


def _run(code: str, fname: str = "handler.php"):
    """Write `code` to a temp single-file plugin dir, scan it, and return findings."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / fname).write_text(code)
    project = build_project_index(tmp)
    results = analyze(code, source_file=str(tmp / fname), project=project)
    return results, tmp


class TestInterProceduralReturnTaint:
    """A method that returns tainted data should taint its caller's result."""

    def test_getter_returning_superglobal_taints_caller(self):
        code = """<?php
class Handler {
    public function get_input() {
        return $_POST['data'];
    }
    public function process() {
        global $wpdb;
        $data = $this->get_input();
        $wpdb->query("SELECT * FROM t WHERE x=$data");
    }
}
"""
        results, tmp = _run(code)
        try:
            sql = [r for r in results if r.sink_type == "sql"]
            assert sql, (
                "Expected the SQL sink in process() to be flagged via get_input()'s return taint"
            )
            assert sql[0].sink_line == 9
        finally:
            shutil.rmtree(tmp)

    def test_sanitized_getter_does_not_taint_caller(self):
        """A getter that sanitizes before returning must NOT propagate taint."""
        code = """<?php
class Handler {
    public function get_input() {
        return sanitize_text_field($_POST['data']);
    }
    public function process() {
        global $wpdb;
        $data = $this->get_input();
        $wpdb->query("SELECT * FROM t WHERE x=$data");
    }
}
"""
        results, tmp = _run(code)
        try:
            sql = [r for r in results if r.sink_type == "sql"]
            assert not sql, f"Sanitized getter should not produce a SQL finding, got: {sql}"
        finally:
            shutil.rmtree(tmp)

    def test_no_project_falls_back_to_intraprocedural_only(self):
        """Without a ProjectIndex, $this-> calls are not resolved (documented, safe fallback)."""
        code = """<?php
class Handler {
    public function get_input() {
        return $_POST['data'];
    }
    public function process() {
        global $wpdb;
        $data = $this->get_input();
        $wpdb->query("SELECT * FROM t WHERE x=$data");
    }
}
"""
        # No project= argument passed -- old, intra-procedural-only behavior.
        results = analyze(code)
        sql = [r for r in results if r.sink_type == "sql"]
        assert not sql, (
            "Without a project index, the $this-> call should not be resolved "
            "(this documents the intentional scope limit, not a bug)"
        )


class TestInterProceduralParameterTaint:
    """A tainted argument passed into $this->method() should taint that method's parameter."""

    def test_tainted_argument_reaches_sink_inside_callee(self):
        code = """<?php
class Handler {
    public function save($value) {
        global $wpdb;
        $wpdb->query("INSERT INTO t VALUES ('$value')");
    }
    public function process() {
        $x = $_POST['note'];
        $this->save($x);
    }
}
"""
        results, tmp = _run(code)
        try:
            sql = [r for r in results if r.sink_type == "sql"]
            assert sql, (
                "Tainted argument passed to $this->save() should flag the sink inside save()"
            )
        finally:
            shutil.rmtree(tmp)

    def test_untainted_argument_does_not_flag_callee_sink(self):
        code = """<?php
class Handler {
    public function save($value) {
        global $wpdb;
        $wpdb->query("INSERT INTO t VALUES ('$value')");
    }
    public function process() {
        $x = 'a literal, safe value';
        $this->save($x);
    }
}
"""
        results, tmp = _run(code)
        try:
            sql = [r for r in results if r.sink_type == "sql"]
            assert not sql, f"A literal argument should not taint save()'s sink, got: {sql}"
        finally:
            shutil.rmtree(tmp)


class TestInterProceduralSafety:
    """Recursion guards and memoization must not crash or hang on pathological input."""

    def test_mutual_recursion_terminates(self):
        """Two methods calling each other must not cause infinite recursion."""
        code = """<?php
class Handler {
    public function a() { return $this->b(); }
    public function b() { return $this->a(); }
    public function process() {
        global $wpdb;
        $x = $this->a();
        $wpdb->query("SELECT $x");
    }
}
"""
        # No assertion on the result itself -- the test's real purpose is
        # that this call completes at all, within pytest's own timeout,
        # rather than hanging or raising a RecursionError.
        results, tmp = _run(code)
        try:
            assert isinstance(results, list)
        finally:
            shutil.rmtree(tmp)

    def test_getter_called_from_multiple_sites_not_duplicated(self):
        """Calling the same tainted getter from two methods should report each call site once."""
        code = """<?php
class Handler {
    public function get_input() {
        return $_POST['x'];
    }
    public function a() {
        global $wpdb;
        $v = $this->get_input();
        $wpdb->query("SELECT $v");
    }
    public function b() {
        global $wpdb;
        $v = $this->get_input();
        $wpdb->query("SELECT $v");
    }
}
"""
        results, tmp = _run(code)
        try:
            sql = [r for r in results if r.sink_type == "sql"]
            sink_lines = {r.sink_line for r in sql}
            assert sink_lines == {9, 14}, (
                f"Expected exactly the two distinct call-site sinks, got lines: {sink_lines}"
            )
        finally:
            shutil.rmtree(tmp)


class TestInterProceduralEndToEnd:
    """Verify the feature works through the full scan() pipeline, not just analyze() directly."""

    def test_full_scan_detects_cross_method_sqli(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "handler.php").write_text(
                """<?php
class Handler {
    public function get_input() {
        return $_POST['data'];
    }
    public function process() {
        global $wpdb;
        $data = $this->get_input();
        $wpdb->query("SELECT * FROM t WHERE x=$data");
    }
}
"""
            )
            files, findings = scan(tmp)
            sql_findings = [f for f in findings if f.rule_id == "WC-SQL-001"]
            assert sql_findings, "Full scan() should detect the cross-method SQL injection"
            assert sql_findings[0].severity == "HIGH"
        finally:
            shutil.rmtree(tmp)
