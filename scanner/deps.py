"""
deps.py – dependency & secret-oriented scanning for plugin roots.

- Parse composer.json / composer.lock for risky packages & outdated hints
- Optional: run `composer audit` if composer is on PATH
- Static secret patterns (complements rules/secrets.py)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding

# Packages historically associated with abandoned / high-risk patterns (heuristic)
_RISKY_NAME = re.compile(
    r"(eval-html|php-shell|backdoor|filesman)",
    re.I,
)

_SECRET_ASSIGN = re.compile(
    r"""(?ix)
    (?:
      (?:api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|
         client[_-]?secret|auth[_-]?token|password|passwd|aws_secret)
      \s*=\s*
      ['\"]([^'\"]{8,})['\"]
    )
    """
)

_ENV_SECRET = re.compile(r"(?i)(sk_live_|rk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})")
# Live-credential patterns that REQUIRE a real credential body (a long run
# of alphanumeric characters) immediately after the prefix.
#
# _ENV_SECRET above matches the bare prefix anywhere on a line, which
# produced two real false positives found while scanning
# woocommerce-gateway-stripe:
#   - A UI description string: 'Only values starting with "sk_live_" ...
#     will be saved.' -- here "sk_live_" is immediately followed by a
#     closing quote, never by an actual key body.
#   - A PHPDoc example: '... sk_live_...JLWaeq.' -- here it's followed by
#     literal dots, not a real key.
# Requiring 16+ alphanumeric characters after the prefix distinguishes
# "a sentence that mentions the prefix" from "an actual leaked key",
# without needing to know the exact real-world key length. AKIA/ghp_
# already had explicit body-length requirements; this brings sk_live_/
# rk_live_ in line with the same standard.
_ENV_SECRET_STRICT = re.compile(
    r"(?i)(sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})"
)

# Precompiled once at import time instead of being passed as literal
# strings to the module-level re.search() function on every call. This
# loop runs per LINE of every scanned config-like file (up to 400 files),
# so re-passing these as string literals to re.search() ~1M times in a
# real scan adds up -- profiling a real 202-file scan showed roughly
# 230,000 calls into re's internal compile-cache-lookup machinery
# attributable to just these three patterns. See owasp_top10.py's
# equivalent precompiled-pattern section for the same fix applied there
# earlier; this file's per-line loop had the identical issue and had
# simply never been profiled until now.
_OPTION_KEY_BUILDER = re.compile(r"\{\$")
_SHARED_SECRET_BUILDER = re.compile(r"shared_secret_\{")
_PLACEHOLDER_LINE = re.compile(
    r"(your-|changeme|example|xxx|placeholder|<.*>|get_option|prefix)", re.I
)


def _is_comment_line(line: str) -> bool:
    """
    True if `line` is a full-line comment (//, #, *, or a /* block opener).

    Neither the live-credential scan nor the generic secret-assignment
    scan below previously filtered comment lines at all, which is how the
    PHPDoc example ('... sk_live_...JLWaeq.' inside a /** ... */ block)
    slipped through as a false positive -- see the _ENV_SECRET_STRICT
    docstring above for the paired length-based fix that also covers this
    case, but comment filtering is kept too as defense in depth for
    examples that happen to use a full-length placeholder key.
    """
    stripped = line.lstrip()
    return stripped.startswith(("//", "#", "*", "/*"))


def _finding(**kwargs: object) -> Finding:
    # NOTE: this default previously was the bare string "A06" (missing
    # both the year suffix and category name, and pointing at the wrong
    # category besides). Four composer/dependency findings in this file
    # relied on this default rather than passing an explicit owasp=
    # argument, so they were silently mis-tagged as "Insecure Design"
    # (A06) instead of "Software Supply Chain Failures" (A03) -- the
    # category composer/dependency issues actually belong to.
    defaults = {
        "owasp": "A03:2025-Software Supply Chain Failures",
        "confidence": 0.6,
        "evidence": "",
        "source": "",
        "sink": "",
    }
    defaults.update(kwargs)
    # mypy cannot verify that **defaults matches Finding's per-field types
    # here, since defaults is a heterogeneous dict built from **kwargs.
    # The keys/types are correct at every call site (see the calls below);
    # this is a structural limitation of unpacking a dict into a dataclass
    # constructor, not a real type error.
    return Finding(**defaults)  # type: ignore[arg-type]


def scan_composer(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    lock = root / "composer.lock"
    manifest = root / "composer.json"

    packages: list[dict] = []
    if lock.is_file():
        try:
            data = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
            packages = list(data.get("packages") or []) + list(data.get("packages-dev") or [])
        except json.JSONDecodeError:
            findings.append(
                _finding(
                    rule_id="WC-OWASP-003",
                    severity="LOW",
                    title="composer.lock is not valid JSON",
                    file="composer.lock",
                    line=1,
                    message="Could not parse composer.lock.",
                    confidence=0.9,
                )
            )
    elif manifest.is_file():
        findings.append(
            _finding(
                rule_id="WC-OWASP-003",
                severity="LOW",
                title="composer.json without composer.lock",
                file="composer.json",
                line=1,
                message="Lockfile missing – dependency versions may drift in CI/production.",
                confidence=0.7,
            )
        )

    for pkg in packages:
        name = str(pkg.get("name") or "")
        version = str(pkg.get("version") or "")
        if _RISKY_NAME.search(name):
            findings.append(
                _finding(
                    rule_id="WC-OWASP-003",
                    severity="HIGH",
                    title=f"Potentially risky Composer package: {name}",
                    file="composer.lock",
                    line=1,
                    message=f"Package {name}@{version} matches a high-risk name heuristic.",
                    confidence=0.75,
                    source=name,
                    sink="composer",
                )
            )

    # composer audit (optional)
    if shutil.which("composer") and (lock.is_file() or manifest.is_file()):
        try:
            proc = subprocess.run(
                ["composer", "audit", "--format=json", "--no-interaction"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.stdout.strip():
                try:
                    audit = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    audit = {}
                # composer audit formats vary; handle common shapes
                advisories: list = []
                if isinstance(audit, dict):
                    advisories = audit.get("advisories") or audit.get("abandoned") or []
                    if isinstance(advisories, dict):
                        # name -> list
                        for pkg_name, items in advisories.items():
                            if not isinstance(items, list):
                                items = [items]
                            for item in items:
                                title = item.get("title") if isinstance(item, dict) else str(item)
                                findings.append(
                                    _finding(
                                        rule_id="WC-OWASP-003",
                                        severity="HIGH",
                                        title=f"Composer audit: {pkg_name}",
                                        file="composer.lock",
                                        line=1,
                                        message=str(title)[:300],
                                        confidence=0.9,
                                        source=str(pkg_name),
                                        sink="composer audit",
                                        owasp="A03:2025-Software Supply Chain Failures",
                                    )
                                )
                elif isinstance(advisories, list):
                    for item in advisories:
                        findings.append(
                            _finding(
                                rule_id="WC-OWASP-003",
                                severity="HIGH",
                                title="Composer audit advisory",
                                file="composer.lock",
                                line=1,
                                message=str(item)[:300],
                                confidence=0.85,
                            )
                        )
        except (subprocess.TimeoutExpired, OSError):
            pass

    return findings


def scan_secrets_files(root: Path) -> list[Finding]:
    """Extra secret pass on config-like files."""
    findings: list[Finding] = []
    patterns = ("*.php", "*.env", "*.yml", "*.yaml", "*.json", "*.ini")
    skip = {".git", "vendor", "node_modules", "tests", "test"}
    resolved_root = root.resolve()
    files: list[Path] = []
    for pat in patterns:
        for p in root.rglob(pat):
            if any(s in p.parts for s in skip):
                continue
            if not p.is_file():
                continue
            # SECURITY: same containment check as utils.php_files() -- see
            # its docstring for why. This function has its own independent
            # rglob() call (rather than reusing php_files()), so it needs
            # its own copy of the same check; without it, a symlinked file
            # pointing outside `root` would bypass the fix applied there
            # and still leak external file content into secret findings.
            try:
                resolved_p = p.resolve()
            except OSError:
                continue
            if not resolved_p.is_relative_to(resolved_root):
                continue
            files.append(p)
            if len(files) > 400:
                break

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for i, line in enumerate(text.splitlines(), 1):
            # Skip comment lines -- see _is_comment_line() docstring for
            # the PHPDoc-example false positive this closes.
            if _is_comment_line(line):
                continue
            # Skip option-key builders: "{$prefix}shared_secret_{$key}"
            if _OPTION_KEY_BUILDER.search(line) or _SHARED_SECRET_BUILDER.search(line):
                continue
            if _PLACEHOLDER_LINE.search(line):
                continue
            # Live token patterns only (not variable names containing 'secret')
            live = _ENV_SECRET_STRICT.search(line)
            assign = _SECRET_ASSIGN.search(line)
            if live:
                findings.append(
                    _finding(
                        rule_id="WC-SECRET-002",
                        severity="HIGH",
                        title="Possible hardcoded secret",
                        file=rel,
                        line=i,
                        message="String looks like a live API key/token. Verify and rotate if real.",
                        confidence=0.85,
                        owasp="A04:2025-Cryptographic Failures",
                        evidence=line.strip()[:120],
                        source="literal",
                        sink="config",
                    )
                )
            elif assign:
                val = assign.group(1)
                if "{" in val or val.startswith("$") or len(val) < 16:
                    continue
                findings.append(
                    _finding(
                        rule_id="WC-SECRET-002",
                        severity="HIGH",
                        title="Possible hardcoded secret",
                        file=rel,
                        line=i,
                        message="Secret-looking assignment. Verify and rotate if real.",
                        confidence=0.7,
                        owasp="A04:2025-Cryptographic Failures",
                        evidence=line.strip()[:120],
                        source="literal",
                        sink="config",
                    )
                )
    return findings


def scan_dependencies(root: Path) -> list[Finding]:
    return scan_composer(root) + scan_secrets_files(root)
