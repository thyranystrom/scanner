"""
test_security_self.py
------------------------
The scanner's own security: permanent regression tests for two real
vulnerabilities found by testing the scanner against its own worst-case
input, rather than assuming a security tool is automatically secure.

1. Path traversal via symlinks (utils.php_files): a plugin directory
   containing a symlinked .php file that points outside the intended scan
   root used to be silently followed, read, and analyzed as if it were
   part of the plugin. Since this tool's entire purpose is scanning
   untrusted, downloaded third-party code, this is not a theoretical
   concern -- a malicious or compromised plugin package could ship a
   symlink to wp-config.php, an SSH key, or any other sensitive file on
   the scanning machine.

2. Incomplete secret redaction (models.redact_secrets): only four known
   credential formats (Stripe, AWS, GitHub) were redacted before writing
   a Finding to a JSON/Markdown report. A generic secret -- a plain
   database password, a custom API key shape -- reached reports in full,
   unredacted plaintext.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from scanner.main import build_report, scan
from scanner.models import redact_secrets
from scanner.utils import php_files


class TestSymlinkPathTraversal:
    """utils.php_files() must never return a file outside the given root."""

    def _make_plugin_with_escaping_symlink(self):
        """
        Build:
          <tmp>/plugin/legit.php              (real file, inside root)
          <tmp>/plugin/sneaky.php  -> symlink to <tmp>/outside/leaked.php
          <tmp>/outside/leaked.php            (real file, OUTSIDE root)
        Returns (plugin_root, outside_dir) for cleanup by the caller.
        """
        base = Path(tempfile.mkdtemp())
        plugin = base / "plugin"
        outside = base / "outside"
        plugin.mkdir()
        outside.mkdir()

        (plugin / "legit.php").write_text("<?php echo 'legit';\n")
        (outside / "leaked.php").write_text("<?php $db_password = 'RealProductionSecret2024!';\n")
        try:
            (plugin / "sneaky.php").symlink_to(outside / "leaked.php")
        except OSError:
            # Symlinks may be unavailable/require elevated privileges on
            # some platforms (notably Windows without developer mode). The
            # containment check is still exercised by the other tests in
            # this class; skip gracefully rather than failing the suite.
            return None, None
        return plugin, base

    def test_symlinked_file_outside_root_is_excluded(self):
        plugin, base = self._make_plugin_with_escaping_symlink()
        if plugin is None:
            return  # symlinks unavailable on this platform
        try:
            files = php_files(plugin)
            names = {f.name for f in files}
            assert "sneaky.php" not in names, (
                "A symlink pointing outside the scan root must not be followed"
            )
            assert "legit.php" in names, "A real file inside the root must still be scanned"
        finally:
            shutil.rmtree(base)

    def test_full_scan_does_not_read_content_outside_root(self):
        """End-to-end: the outside file's content must never appear in any finding."""
        plugin, base = self._make_plugin_with_escaping_symlink()
        if plugin is None:
            return
        try:
            files, findings = scan(plugin)
            for f in findings:
                assert "RealProductionSecret2024" not in (f.evidence or ""), (
                    "Content from outside the scan root leaked into a finding"
                )
                assert "RealProductionSecret2024" not in (f.message or "")
        finally:
            shutil.rmtree(base)

    def test_symlinked_directory_outside_root_is_not_traversed(self):
        """A symlinked directory must not let files outside the root be discovered."""
        base = Path(tempfile.mkdtemp())
        plugin = base / "plugin"
        outside = base / "outside_dir"
        plugin.mkdir()
        outside.mkdir()
        (outside / "leaked.php").write_text("<?php $secret = 'x';\n")
        try:
            (plugin / "escaped_link").symlink_to(outside)
        except OSError:
            shutil.rmtree(base)
            return
        try:
            files = php_files(plugin)
            for f in files:
                assert f.resolve().is_relative_to(plugin.resolve()), (
                    f"File {f} escaped the intended scan root via a symlinked directory"
                )
        finally:
            shutil.rmtree(base)


class TestSecretRedaction:
    """models.redact_secrets() must not leak any secret-shaped value verbatim."""

    def test_generic_password_is_redacted(self):
        raw = "1: $db_password = 'MyRealProductionDbPassword2024!';"
        redacted = redact_secrets(raw)
        assert "MyRealProductionDbPassword2024!" not in redacted
        assert "[REDACTED]" in redacted

    def test_known_stripe_format_keeps_informative_prefix(self):
        raw = "1: $api_key = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';"
        redacted = redact_secrets(raw)
        assert "abcdefghijklmnopqrstuvwxyz123456" not in redacted
        assert "sk_live_[REDACTED]" in redacted, (
            "Known credential formats should keep their prefix for readability"
        )

    def test_known_aws_format_still_redacted(self):
        raw = "1: $aws_key = 'AKIAIOSFODNN7EXAMPLE';"
        redacted = redact_secrets(raw)
        assert "IOSFODNN7EXAMPLE" not in redacted

    def test_generic_pass_does_not_double_redact_known_format(self):
        """The generic fallback must not clobber layer 1's more informative output."""
        raw = "1: $secret_key = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';"
        redacted = redact_secrets(raw)
        assert redacted.count("REDACTED") == 1, (
            f"Expected exactly one redaction marker, got: {redacted}"
        )
        assert "sk_live_[REDACTED]" in redacted

    def test_non_secret_text_is_unchanged(self):
        raw = "1: echo 'hello world';"
        assert redact_secrets(raw) == raw

    def test_end_to_end_report_never_contains_raw_secret_value(self):
        """Full pipeline: build_report()'s output must never contain a raw secret value."""
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "settings.php").write_text(
                "<?php $webhook_secret = 'CompletelyCustomSecretFormat987';\n"
            )
            files, findings = scan(tmp)
            report = build_report(tmp, files, findings)
            report_text = str(report)
            assert "CompletelyCustomSecretFormat987" not in report_text, (
                "A secret value leaked into the report unredacted"
            )
        finally:
            shutil.rmtree(tmp)


class TestAutofixWriteSafety:
    """--fix-apply must never write outside the scan root, and must back up originals."""

    def test_autofix_creates_backup_before_overwriting(self):
        from scanner.main import _apply_to_disk, _build_fixes

        tmp = Path(tempfile.mkdtemp())
        try:
            target = tmp / "handler.php"
            # A tainted-variable-in-echo (WC-XSS-001) fix reaches >= 0.90
            # confidence and is a known auto-applicable fix.
            original = '<?php\n$id = $_GET["id"];\necho $id;\n'
            target.write_text(original)

            files, findings = scan(tmp)
            fixes_by_fp, source_map = _build_fixes(tmp, findings)
            _apply_to_disk(tmp, fixes_by_fp, source_map)

            backup = target.with_suffix(target.suffix + ".bak")
            assert backup.exists(), "Expected a .bak file to be created before overwriting"
            assert backup.read_text() == original, "Backup must contain the pre-fix content"
        finally:
            shutil.rmtree(tmp)

    def test_autofix_refuses_to_write_outside_root_via_symlink(self):
        """
        Defense-in-depth: even if a Finding's file path somehow pointed
        outside the scan root, _apply_to_disk must refuse to write there.
        """
        from scanner.autofix import CodeFix
        from scanner.main import _apply_to_disk

        tmp = Path(tempfile.mkdtemp())
        outside = tmp.parent / "wc-scanner-test-outside.php"
        try:
            root = tmp / "plugin"
            root.mkdir()
            outside.write_text("<?php $x = 1;\n")

            # Simulate a fix whose file path escapes the intended root
            # (normally impossible via the normal scan() flow after the
            # php_files() containment fix, but this test exists precisely
            # so that guarantee doesn't silently depend on that alone).
            escaping_path = "../wc-scanner-test-outside.php"
            fix = CodeFix(
                rule_id="WC-SECRET-001",
                file=escaping_path,
                line=1,
                original_line="<?php $x = 1;",
                fixed_line="<?php $x = 2;",
                description="test",
                confidence=0.95,
            )
            fixes_by_fp = {"fake-fp": fix}
            source_map = {escaping_path: "<?php $x = 1;\n"}

            _apply_to_disk(root, fixes_by_fp, source_map)

            assert outside.read_text() == "<?php $x = 1;\n", (
                "A fix path escaping the scan root must never be written to disk"
            )
        finally:
            shutil.rmtree(tmp)
            outside.unlink(missing_ok=True)


class TestBaselineWriteSafety:
    """--write-baseline must use the same symlink-safe atomic write as --json/--md."""

    def test_write_baseline_refuses_to_follow_symlink(self):
        from scanner.main import _write_text_safely

        tmp = Path(tempfile.mkdtemp())
        try:
            real_target = tmp / "real_file.json"
            real_target.write_text("original content")
            link = tmp / "baseline.json"
            try:
                link.symlink_to(real_target)
            except OSError:
                return  # symlinks unavailable on this platform

            raised = False
            try:
                _write_text_safely(link, "new content")
            except SystemExit:
                raised = True

            assert raised, "_write_text_safely must refuse to write through a symlink"
            assert real_target.read_text() == "original content", (
                "The symlink target must not be overwritten"
            )
        finally:
            shutil.rmtree(tmp)


class TestNewlineFilenameProtocolSafety:
    """
    ast_engine.get_ast_batch() sends one absolute file path per line to a
    PHP subprocess over stdin. Linux/macOS filesystems allow a literal
    newline character inside a filename (only '/' and NUL are actually
    forbidden), so a crafted filename containing '\\n' would inject what
    looks like a second, attacker-influenced "path" into that stream --
    undefined behavior a security tool scanning untrusted plugin packages
    has no business accepting. php_files() now rejects any path
    containing '\\n' or '\\r' before it's ever considered for scanning.
    """

    def test_newline_in_filename_is_excluded(self):
        from scanner.utils import php_files

        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "legit.php").write_text("<?php echo 1;")
            try:
                evil = tmp / "weird.php\ninjected.php"
                evil.write_text("<?php echo 1;")
            except OSError:
                return  # filesystem doesn't allow it -- nothing to test here

            files = php_files(tmp)
            names = {f.name for f in files}
            assert not any("\n" in n for n in names), (
                "A filename containing a newline must never be scanned"
            )
            assert "legit.php" in names, "A normal file in the same directory must still be found"
        finally:
            shutil.rmtree(tmp)
