from pathlib import Path

EXCLUDED_PARTS = {
    "vendor",
    "dependencies",
    "node_modules",
    ".git",
    ".github",
    "docs",
    "tests",
    "test",
    "testsuite",
}


def php_files(root: Path):
    """
    Recursively find every .php file under `root`.

    SECURITY: verifies each matched file's fully-resolved (symlink-following)
    absolute path is actually contained within `root` before including it.

    Without this check, a plugin directory containing a symlinked file that
    points outside the scan root (e.g. a file literally named
    "innocent-looking.php" that is really a symlink to a nearby
    wp-config.php, an SSH private key, or any other file on the scanning
    machine) would be silently followed, read, and analyzed as if it were
    part of the plugin -- exactly the kind of malicious payload a hostile
    or compromised third-party plugin package could ship. This matters
    specifically for this tool because its entire purpose is scanning
    untrusted, downloaded code: the threat model this closes is not
    theoretical.

    Symlinked *directories* are handled the same way: if rglob() happens to
    descend into one (behavior here differs across Python versions and
    platforms -- it is not something to rely on implicitly), every file
    found through it is still subject to this same containment check.
    """
    resolved_root = root.resolve()
    result = []
    for p in root.rglob("*.php"):
        if not p.is_file():
            continue
        if any(part in EXCLUDED_PARTS for part in p.parts):
            continue
        try:
            resolved_p = p.resolve()
        except OSError:
            continue  # broken symlink or unresolvable path -- skip silently
        if not resolved_p.is_relative_to(resolved_root):
            continue  # escapes the scan root via a symlink -- do not follow
        if "\n" in str(resolved_p) or "\r" in str(resolved_p):
            # A filename containing a literal newline/carriage-return is
            # legal on Linux/macOS filesystems (only '/' and NUL are
            # actually forbidden in a path component), but this scanner's
            # batch AST-parsing protocol (ast_engine.get_ast_batch) sends
            # one absolute path per line to a PHP subprocess over stdin.
            # A filename containing '\n' would inject what looks like a
            # second, attacker-influenced "path" into that stream, which
            # the PHP side would then separately attempt to read --
            # undefined behavior this tool has no business accepting. No
            # legitimate plugin ships a file named this way; skip it the
            # same way a broken symlink is silently skipped.
            continue
        result.append(p)
    return sorted(result)


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def snippet(lines, line_no, radius=2):
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(f"{i + 1:4}: {lines[i]}" for i in range(start, end))


def context_after(text: str, start: int, limit: int = 2500) -> str:
    return text[start : start + limit]


def has_any(text: str, patterns) -> bool:
    return any(p in text for p in patterns)


_OWASP_LABELS = {
    "A01": "A01:2025-Broken Access Control",
    "A02": "A02:2025-Security Misconfiguration",
    "A03": "A03:2025-Software Supply Chain Failures",
    "A04": "A04:2025-Cryptographic Failures",
    "A05": "A05:2025-Injection",
    "A06": "A06:2025-Insecure Design",
    "A07": "A07:2025-Authentication Failures",
    "A08": "A08:2025-Software or Data Integrity Failures",
    "A09": "A09:2025-Security Logging and Alerting Failures",
    "A10": "A10:2025-Mishandling of Exceptional Conditions",
}


def format_owasp(raw: str | None) -> str:
    if not raw:
        return "OWASP-N/A"
    s = str(raw).strip()
    if "2025" in s:
        return s
    code = s[:3].upper() if len(s) >= 3 and s[0].upper() == "A" else s.upper()
    return _OWASP_LABELS.get(code, s)
