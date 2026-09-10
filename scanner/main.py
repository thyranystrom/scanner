"""
main.py
-------
CLI entry point and the scan() orchestrator.

Performance design:
  - Each PHP file is read and parsed exactly once; the text and AST
    are reused by every rule module that needs them.
  - The AST cache is cleared at the start of every scan() call, so
    repeated invocations always see fresh data.
  - Files are scanned in parallel via concurrent.futures.ThreadPoolExecutor.
    The PHP subprocess calls (ASTEngine) are I/O-bound, so threads win
    a lot from parallelism here.
    Worker count = min(CPU cores, 8) -- conservative to avoid
    overloading disk I/O on very large repositories.
  - build_project_index() runs exactly ONCE before the file loop, not per file.
  - Autofix generation (_build_fixes) runs once after the scan completes,
    not once per finding.

Usage:
  python -m scanner.main path/to/plugin
  python -m scanner.main path/to/plugin --triage
  python -m scanner.main path/to/plugin --md reports/out.md --fail-on-severity HIGH
  python -m scanner.main path/to/plugin --fix-apply
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import VERSION
from .ast_cache import cache_stats as _cache_stats
from .ast_cache import clear_cache as _clear_ast_cache
from .autofix import FixEngine, apply_fixes
from .dataflow import _engine as _ast_engine  # shared singleton
from .dataflow import clear_analyze_cache as _clear_analyze_cache
from .deps import scan_dependencies
from .limits import ScanLimits, select_files
from .models import Finding
from .printer import Printer
from .project import build_project_index
from .rules import RULES
from .triage import manual_review_queue, split_by_severity, triage_lines
from .utils import php_files

SCANNER_NAME = "woocommerce-security-scanner"
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Number of parallel workers for file scanning.
# ThreadPoolExecutor works well here because the bottleneck is I/O (PHP subprocess calls).
_MAX_WORKERS = min(os.cpu_count() or 1, 8)

_fix_engine = FixEngine()


# ---------------------------------------------------------------------------
# Markdown-rapport
# ---------------------------------------------------------------------------


def generate_markdown_report(report: dict) -> str:
    md = []
    md.append("# 🛡️ WooCommerce Security Scan Report\n")
    md.append(f"**Target:** `{report.get('target', '')}`  ")
    md.append(f"**PHP Files Scanned:** {report['summary'].get('php_files_scanned', 0)}  ")
    md.append(f"**Total Findings:** {report['summary'].get('findings', 0)}\n")

    if report["summary"].get("baseline_suppressed"):
        md.append(
            f"> ℹ️ **Baseline:** "
            f"{report['summary']['baseline_suppressed']} known finding(s) suppressed.\n"
        )

    findings = report.get("findings", [])
    if not findings:
        md.append("✅ **No security issues found.**\n")
    else:
        md.append("## 🚨 Findings\n")
        md.append("| # | Severity | Rule | Location | Title |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for idx, f in enumerate(findings, 1):
            loc = f"`{f.get('file', '')}:{f.get('line', '')}`"
            md.append(
                f"| {idx} | **{f.get('severity', '')}** | `{f.get('rule_id', '')}` "
                f"| {loc} | {f.get('title', '')} |"
            )
        md.append("\n---\n")
        md.append("## 💡 Fix Suggestions\n")
        for idx, f in enumerate(findings, 1):
            fix = f.get("autofix")
            md.append(
                f"### #{idx} `{f.get('rule_id', '')}` — {f.get('file', '')}:{f.get('line', '')}\n"
            )
            if fix:
                can = "✓ Auto-applicable" if fix.get("auto_apply") else "⚠ Review"
                md.append(f"**{can}** (conf {fix.get('confidence', 0):.0%})\n")
                md.append(f"```diff\n{fix.get('diff', '')}\n```\n")
                if fix.get("references"):
                    md.append(f"→ {fix['references'][0]}\n")
            else:
                md.append(f"> {f.get('message', '').replace(chr(10), ' ')}\n")

    return "\n".join(md)


# ---------------------------------------------------------------------------
# Scan core
# ---------------------------------------------------------------------------


def fingerprint_of(f) -> str:
    if isinstance(f, Finding):
        return f.fingerprint()
    if isinstance(f, dict) and f.get("fingerprint"):
        return str(f["fingerprint"])
    return Finding(
        rule_id=str(f.get("rule_id", "")),
        severity=str(f.get("severity", "INFO")),
        title=str(f.get("title", "")),
        file=str(f.get("file", "")),
        line=int(f.get("line") or 0),
        message=str(f.get("message", "")),
        owasp=str(f.get("owasp", "")),
        confidence=float(f.get("confidence") or 0),
        source=f.get("source"),
        sink=f.get("sink"),
    ).fingerprint()


def _scan_file(path: Path, root: Path, project) -> list[Finding]:
    """
    Scan a single PHP file against every rule and return its findings.
    Runs inside a ThreadPoolExecutor worker, in parallel with other files.

    Pre-warming: calls get_ast() once, before the rule loop below starts.
    By this point scan()'s batch pre-warm (get_ast_batch, called once for
    every file before this parallel loop even begins) has already parsed
    this file, so this call is normally a pure in-memory cache hit with no
    subprocess spawn at all. It's kept as a safety fallback for any file
    that somehow wasn't covered by the batch (e.g. added between file
    discovery and this point), in which case it transparently falls back
    to a single-file PHP call.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Pre-warm the AST cache using the real file path (see docstring above)
    _ast_engine.get_ast(str(path))

    rel = path.relative_to(root)
    results = []
    for rule in RULES:
        try:
            results.extend(rule(rel, text, project=project))
        except TypeError:
            results.extend(rule(rel, text))
        except Exception:
            pass  # a single rule crashing must not abort the entire scan
    return results


# Rules that are "source-only" – drop when a stronger sink finding exists
# on the same file + line (or same file + nearby taint source line).
_SOURCE_RULES = frozenset(
    {
        "WC-INPUT-001",
        "WC-INPUT-002",
        "WC-INPUT-003",
    }
)
_SINK_RULES = frozenset(
    {
        "WC-SQL-001",
        "WC-XSS-001",
        "WC-OUTPUT-001",
        "WC-DANGER-001",
        "WC-OWASP-001",
        "WC-OWASP-008",
        "WC-OWASP-010",
    }
)
# Weaker sibling rules suppressed when a stronger one hits the same line
_DOMINATED = {
    # medium generic SQL review dominated by taint SQL on same line
    "WC-SQL-001:medium_review": "WC-SQL-001:taint",
    "WC-SECRET-002": "WC-SECRET-001",  # same secret, prefer richer rule
    "WC-OUTPUT-001": "WC-XSS-001",  # same echo, prefer taint XSS
}


def _sev_rank(sev: str) -> int:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    try:
        return order.index(sev)
    except ValueError:
        return 99


def _is_taint_sql(f) -> bool:
    return getattr(f, "rule_id", "") == "WC-SQL-001" and (
        getattr(f, "flow_type", None) == "taint" or "Tainted" in (getattr(f, "title", "") or "")
    )


def _is_review_sql(f) -> bool:
    title = (getattr(f, "title", "") or "").lower()
    return getattr(f, "rule_id", "") == "WC-SQL-001" and "review" in title


def dedupe_semantic(findings: list) -> list:
    """
    Collapse overlapping findings so one issue is not reported multiple times.

    Rules:
      1. Same file+line+rule_id → keep highest severity/confidence only.
      2. SECRET-002 dropped if SECRET-001 on same file+line.
      3. OUTPUT-001 dropped if XSS-001 on same file+line.
      4. Generic SQL "should be reviewed" dropped if taint SQL on same file+line.
      5. INPUT-* dropped if a sink finding (SQL/XSS/DANGER/OWASP) exists on
         the same file+line, or INPUT line equals another finding's taint_line.
    """
    if not findings:
        return findings

    def key_fl(f):
        return (str(f.file).replace("\\", "/").lower(), int(f.line or 0))

    # Pass 1: same file+line+rule_id → best only
    best: dict = {}
    for f in findings:
        k = (*key_fl(f), f.rule_id)
        prev = best.get(k)
        if prev is None:
            best[k] = f
            continue
        if (_sev_rank(f.severity), -f.confidence) < (_sev_rank(prev.severity), -prev.confidence):
            best[k] = f
    findings = list(best.values())

    by_fl: dict[tuple, list] = {}
    for f in findings:
        by_fl.setdefault(key_fl(f), []).append(f)

    # Lines that have sink findings
    sink_lines: set[tuple] = set()
    taint_sources: set[tuple] = set()  # (file, taint_line)
    for f in findings:
        rid = f.rule_id
        if rid in _SINK_RULES or _is_taint_sql(f):
            sink_lines.add(key_fl(f))
        tl = getattr(f, "taint_line", None)
        if tl:
            taint_sources.add((str(f.file).replace("\\", "/").lower(), int(tl)))

    drop: set[int] = set()
    for i, f in enumerate(findings):
        fl = key_fl(f)
        peers = by_fl.get(fl, [])
        rid = f.rule_id

        # SECRET-002 if SECRET-001 same line
        if rid == "WC-SECRET-002" and any(p.rule_id == "WC-SECRET-001" for p in peers):
            drop.add(i)
            continue
        # OUTPUT if XSS same line
        if rid == "WC-OUTPUT-001" and any(p.rule_id == "WC-XSS-001" for p in peers):
            drop.add(i)
            continue
        # Weak SQL review if taint SQL same line
        if _is_review_sql(f) and any(_is_taint_sql(p) for p in peers):
            drop.add(i)
            continue
        # INPUT if sink on same line or this line is a taint source for a sink
        if rid in _SOURCE_RULES:
            if fl in sink_lines:
                drop.add(i)
                continue
            if fl in taint_sources:
                drop.add(i)
                continue
            # also: any peer on same line is a sink rule
            if any(p.rule_id in _SINK_RULES or _is_taint_sql(p) for p in peers):
                drop.add(i)
                continue

    return [f for i, f in enumerate(findings) if i not in drop]


def scan(
    root: Path, *, with_deps: bool = True, max_workers: int = _MAX_WORKERS
) -> tuple[list, list]:
    """
    Scan every PHP file under root in parallel.

    Steps:
      1. Clear the AST cache (guarantees fresh data across repeated calls).
      2. Build a ProjectIndex (reads every file once, for cross-file symbol lookup).
      3. Run _scan_file in parallel via ThreadPoolExecutor.
      4. Deduplicate findings by fingerprint; sort by severity, then by line.
    """
    # 1. Start this run with a clean AST cache
    _ast_engine.clear_cache()
    _clear_analyze_cache()

    files = list(php_files(root))
    # Bound resource consumption on untrusted, potentially huge or
    # adversarial source trees (a malicious plugin package could ship a
    # single multi-gigabyte .php file, or hundreds of thousands of tiny
    # ones, purely to exhaust memory/time). Oversized or excess files are
    # silently skipped rather than read.
    files, _skipped_for_limits = select_files(files, root, ScanLimits())
    project = build_project_index(root)

    # Batch-parse every file's AST in as few PHP subprocess spawns as
    # possible, before the parallel rule-execution loop below starts.
    # This is what turns ~200 individual PHP process spawns (the dominant
    # cost on a cold scan) into a handful of batched calls -- see
    # ast_engine.ASTEngine.get_ast_batch's docstring for the full story.
    # Each file's later get_ast() call then just hits this pre-warmed cache.
    _ast_engine.get_ast_batch([str(p) for p in files])

    # 2. Parallel file scanning
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_file, p, root, project): p for p in files}
        for fut in as_completed(futures):
            with contextlib.suppress(Exception):
                findings.extend(fut.result())

    if with_deps:
        findings.extend(scan_dependencies(root))

    # 3. Deduplicate
    unique, seen = [], set()
    for f in findings:
        fp = f.fingerprint() if hasattr(f, "fingerprint") else fingerprint_of(f)
        if fp not in seen:
            seen.add(fp)
            unique.append(f)

    unique = dedupe_semantic(unique)

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    unique.sort(key=lambda f: (rank.get(f.severity, 99), f.file, f.line))

    # Cross-rule deduplication: when multiple rules fire on the exact same
    # (file, line), keep only the finding with the highest severity.
    # This prevents a single risky line from generating a wall of noise.
    # Example: md5($_POST['pin']) fires both WC-INPUT-002 and WC-OWASP-004 –
    # we keep WC-OWASP-004 (MEDIUM weak-crypto) as it is more specific.
    line_winners: dict[tuple, Finding] = {}
    for f in unique:
        key = (str(f.file).replace("\\", "/"), f.line)
        existing = line_winners.get(key)
        if existing is None:
            line_winners[key] = f
        else:
            # Keep whichever has higher severity (lower rank index = higher severity)
            if rank.get(f.severity, 99) < rank.get(existing.severity, 99) or (
                rank.get(f.severity, 99) == rank.get(existing.severity, 99)
                and "INPUT" in existing.rule_id
                and "INPUT" not in f.rule_id
            ):
                line_winners[key] = f

    unique = sorted(line_winners.values(), key=lambda f: (rank.get(f.severity, 99), f.file, f.line))
    return files, unique


def build_report(root, files, findings, fixes_by_fp: dict | None = None) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    findings_dicts = []
    for f in findings:
        d = f.to_dict()
        fix = (fixes_by_fp or {}).get(f.fingerprint())
        if fix:
            d["autofix"] = fix.to_dict()
        findings_dicts.append(d)

    return {
        "scanner": {"name": SCANNER_NAME, "version": VERSION},
        "target": str(root),
        "summary": {
            "php_files_scanned": len(files),
            "findings": len(findings),
            "finding_counts": counts,
            "manual_review_count": len(manual_review_queue(findings)),
        },
        "findings": findings_dicts,
        "manual_review": [f.to_dict() for f in manual_review_queue(findings)],
    }


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("findings", data if isinstance(data, list) else [])
    return {fingerprint_of(f) for f in items}


def apply_baseline(findings, fps: set[str]):
    new, n = [], 0
    for f in findings:
        if f.fingerprint() in fps:
            n += 1
        else:
            new.append(f)
    return new, n


def _gate(findings, fail_on: str) -> int:
    if not fail_on or fail_on.upper() == "NONE":
        return 0
    order = list(SEVERITY_ORDER)
    fo = fail_on.upper() if fail_on.upper() in order else "HIGH"
    thr = order.index(fo)
    return 1 if any(order.index(f.severity) <= thr for f in findings) else 0


# ---------------------------------------------------------------------------
# Autofix
# ---------------------------------------------------------------------------


def _normalize_path(p: str) -> str:
    """Normalize a path to forward slashes so dict keys work consistently across platforms."""
    return str(p).replace("\\", "/")


def _build_fixes(root: Path, findings: list) -> tuple[dict, dict]:
    """
    Generate CodeFix suggestions for all findings and return:
      fixes_by_fp  – {fingerprint: CodeFix}
      source_map   – {normalized_rel_path: source_text}  (used by --fix-apply)

    Every path is normalized to forward slashes so dict lookups work
    correctly on Windows too, where Path objects otherwise produce
    backslash-separated strings.
    """
    by_file: dict[str, list] = defaultdict(list)
    for f in findings:
        by_file[_normalize_path(f.file)].append(f)

    source_map: dict[str, str] = {}
    for rel_path in by_file:
        try:
            # Use Path() so separators are handled correctly on any OS
            abs_path = root / rel_path.replace("/", os.sep)
            source_map[rel_path] = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass

    fixes_by_fp: dict = {}
    for rel_path, file_findings in by_file.items():
        text = source_map.get(rel_path)
        if not text:
            continue
        for fix in _fix_engine.suggest(file_findings, text):
            # Normalize fix.file so it matches the source_map key format
            fix_path = _normalize_path(fix.file)
            for f in file_findings:
                if f.line == fix.line and f.rule_id == fix.rule_id:
                    # Store the fix with its path normalized
                    import dataclasses

                    norm_fix = dataclasses.replace(fix, file=fix_path)
                    fixes_by_fp[f.fingerprint()] = norm_fix
                    break

    return fixes_by_fp, source_map


def _apply_to_disk(root: Path, fixes_by_fp: dict, source_map: dict) -> None:
    """
    Write high-confidence fixes (>= 0.90) to disk.
    Paths are normalized to forward slashes in fixes_by_fp and source_map.

    SECURITY: re-verifies path containment before writing, even though
    every fix's path already traces back through Finding.file, which
    itself only ever comes from utils.php_files() -- already containment-
    checked at scan time. That chain of trust spans several modules, so
    this is a defense-in-depth check: a future change anywhere in that
    chain (a new way to construct a Finding, a baseline-driven fix path,
    etc.) should not be able to silently turn --fix-apply into a way to
    write outside the scanned directory.

    SAFETY: writes a .bak backup of the original file content before
    overwriting it. Autofix modifies real source code on the user's
    machine; if apply_fixes() ever has a bug, or a specific suggestion
    turns out to be wrong for a given codebase, the original content must
    still be recoverable rather than being irrecoverably lost.
    """
    auto = [f for f in fixes_by_fp.values() if f.confidence >= 0.90]
    if not auto:
        print("  No fixes with confidence >= 0.90 -- nothing written.")
        print("  Review the suggestions above and apply them manually.")
        return

    fixes_by_file: dict[str, list] = defaultdict(list)
    for fix in auto:
        fixes_by_file[_normalize_path(fix.file)].append(fix)

    resolved_root = root.resolve()
    written = 0
    for rel_path, file_fixes in fixes_by_file.items():
        text = source_map.get(rel_path)
        if not text:
            print(f"  ✗  {rel_path}: source not in map (path mismatch?)")
            continue
        try:
            # Rebuild the absolute path using the OS-correct separator
            abs_path = root / rel_path.replace("/", os.sep)
            resolved_target = abs_path.resolve()
        except OSError as e:
            print(f"  ✗  {rel_path}: {e}")
            continue

        if not resolved_target.is_relative_to(resolved_root):
            print(f"  ✗  {rel_path}: refusing to write outside the scan root")
            continue

        patched = apply_fixes(text, file_fixes)
        try:
            # Preserve the original content before overwriting, so a bad
            # fix (or a bug in apply_fixes()) can always be undone.
            backup_path = resolved_target.with_suffix(resolved_target.suffix + ".bak")
            backup_path.write_text(text, encoding="utf-8")
            resolved_target.write_text(patched, encoding="utf-8")
            print(
                f"  ✓  {rel_path}  ({len(file_fixes)} fix(es) applied, backup: {backup_path.name})"
            )
            written += 1
        except OSError as e:
            print(f"  ✗  {rel_path}: {e}")

    if written:
        print(f"\n  {written} file(s) patched. Re-run scanner to verify.")

    print("\n  Re-run the scanner to verify fixes.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_text_safely(path: Path, text: str) -> None:
    """
    Write a report to disk without following an existing symlink at the
    destination, and atomically (write to a temp file, then rename) so a
    process interrupted mid-write never leaves a corrupt, partially-written
    report behind. Mirrors the same "don't trust the filesystem" caution
    already applied to scan input (see utils.php_files' symlink
    containment check) -- here applied to scan OUTPUT instead.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise SystemExit(f"Refusing to overwrite symlink: {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    finally:
        with contextlib.suppress(OSError):
            Path(tmp_name).unlink()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="WooCommerce plugin security scanner",
        epilog="Tip: use --triage for a HIGH/CRITICAL checklist only.",
    )
    parser.add_argument("target", type=Path, nargs="?", help="Plugin directory")
    parser.add_argument("--json", type=Path, help="Write JSON report")
    parser.add_argument("--md", type=Path, help="Write Markdown report")
    parser.add_argument("--baseline", type=Path, help="Suppress known findings")
    parser.add_argument("--write-baseline", type=Path, help="Save findings as baseline")
    parser.add_argument("--triage", action="store_true", help="Show HIGH/CRITICAL only + checklist")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="INFO",
        help="Only show findings at or above this severity (default: INFO, i.e. all)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only show findings at or above this confidence, 0.0-1.0 (default: 0.0, i.e. all)",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"],
        default="HIGH",
        help="Exit with a non-zero code if any finding meets or exceeds this "
        "severity (default: HIGH). Use NONE to always exit 0 -- useful for "
        "CI jobs that should report findings without blocking the pipeline.",
    )
    parser.add_argument("--no-deps", action="store_true", help="Skip composer/secret pass")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors (auto-detected otherwise)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=_MAX_WORKERS,
        help=f"Parallel file-scanning workers, min(CPU cores, 8) "
        f"(default on this machine: {_MAX_WORKERS})",
    )
    parser.add_argument(
        "--fix-apply",
        action="store_true",
        help="Write high-confidence fixes to disk. Back up first.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear the persistent AST cache and exit."
    )
    parser.add_argument(
        "--cache-stats", action="store_true", help="Show AST cache statistics and exit."
    )
    args = parser.parse_args(argv)

    # Allow overriding worker count from CLI
    workers = args.workers

    printer = Printer(colour=False if args.no_color else None)

    if args.clear_cache:
        n = _clear_ast_cache()
        print(f"AST cache cleared: {n} entries removed.")
        return 0

    if args.cache_stats:
        stats = _cache_stats()
        print(
            f"AST cache: {stats['entries']} entries  {stats['size_kb']} KB  ({stats['cache_dir']})"
        )
        return 0

    if args.target is None:
        parser.print_help()
        return 0

    root = args.target.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a directory: {root}")

    printer.banner(VERSION)
    files, all_findings = scan(root, with_deps=not args.no_deps, max_workers=workers)

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    min_r = rank.get(args.min_severity, 99)
    findings = [
        f
        for f in all_findings
        if rank.get(f.severity, 99) <= min_r and f.confidence >= args.min_confidence
    ]

    # Autofix suggestions -- always generated, shown inline per finding
    fixes_by_fp, source_map = _build_fixes(root, findings)

    if args.write_baseline:
        _write_text_safely(
            args.write_baseline,
            json.dumps(build_report(root, files, findings, fixes_by_fp), indent=2),
        )
        print(f"Baseline written: {args.write_baseline} ({len(findings)} findings)")

    suppressed = 0
    if args.baseline:
        if not args.baseline.is_file():
            raise SystemExit(f"Baseline not found: {args.baseline}")
        findings, suppressed = apply_baseline(findings, load_baseline(args.baseline))

    report = build_report(root, files, findings, fixes_by_fp)
    if suppressed:
        report["summary"]["baseline_suppressed"] = suppressed

    buckets = split_by_severity(findings)
    printer.summary(
        target=str(root),
        files_scanned=report["summary"]["php_files_scanned"],
        total_findings=report["summary"]["findings"],
        counts=report["summary"]["finding_counts"],
    )
    if suppressed:
        print(f"  Baseline suppressed: {suppressed}")

    high_n = len(buckets.get("CRITICAL", [])) + len(buckets.get("HIGH", []))
    med_n = len(buckets.get("MEDIUM", []))
    low_n = len(buckets.get("LOW", [])) + len(buckets.get("INFO", []))
    print(f"  Priority   HIGH/CRIT {high_n}  ·  MEDIUM {med_n}  ·  LOW/INFO {low_n}")
    print(f"  Fixes      {len(fixes_by_fp)} auto-suggestion(s) generated inline")
    print(f"  Workers    {workers} parallel")

    show = manual_review_queue(findings) if args.triage else findings

    if args.triage:
        printer.triage_banner(triage_lines(findings))
        if show:
            printer.findings_header()
            for i, f in enumerate(show, 1):
                d = f.to_dict() if hasattr(f, "to_dict") else f
                fix = fixes_by_fp.get(f.fingerprint() if hasattr(f, "fingerprint") else "")
                printer.finding(d, i, fix=fix)
        else:
            printer.no_findings()
    else:
        if findings:
            printer.findings_header()
            for i, f in enumerate(findings, 1):
                d = report["findings"][i - 1]
                fix = fixes_by_fp.get(f.fingerprint())
                printer.finding(d, i, fix=fix)
            if high_n:
                print("\n" + "─" * 72)
                print(f"  → {high_n} item(s) need manual review  (use --triage for checklist)")
                print("─" * 72)
        else:
            printer.no_findings()

    printer.autofix_summary(list(fixes_by_fp.values()))

    if args.fix_apply:
        print("─" * 72)
        print("  Applying high-confidence fixes...")
        _apply_to_disk(root, fixes_by_fp, source_map)

    if args.json:
        _write_text_safely(args.json, json.dumps(report, indent=2))
        printer.json_written(str(args.json))

    if args.md:
        _write_text_safely(args.md, generate_markdown_report(report))
        print(f"\n  Markdown →  {args.md}")

    return _gate(findings, args.fail_on_severity)


if __name__ == "__main__":
    sys.exit(main() or 0)
