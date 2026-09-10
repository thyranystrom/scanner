"""
sql.py
------
Checks if a tainted variable (from dataflow) is used in the query --
only then raises a finding; static string queries are skipped. Confidence
is reduced when prepare() appears anywhere in the surrounding function
block, even if not directly wrapping this call.
"""

import re

from ..dataflow import analyze, resolve_source_file
from ..models import Finding
from ..utils import line_number, snippet

DB_CALLS = re.compile(r"\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(")

# Only suppress if the query is a pure string literal with NO variable
# interpolation (e.g. no $var inside the string) OTHER than a reference
# to a $wpdb->PROPERTY like {$wpdb->prefix} or {$wpdb->postmeta}.
# "$wpdb->query("SELECT * FROM t WHERE id=$id")" must NOT match.
# "$wpdb->query("SELECT * FROM {$wpdb->prefix}orders")" SHOULD match --
# $wpdb->prefix is a static table-name fragment set once in wp-config.php,
# never influenced by user/request data, so it carries the same "no real
# interpolation risk" status as a plain string literal. Without this, the
# single most common line of code in any WordPress plugin's custom-query
# code ({$wpdb->prefix}tablename) triggered a MEDIUM "should be reviewed"
# finding on every occurrence -- noisy enough that a real user would
# likely start ignoring WC-SQL-001 findings altogether.
_STRING_ONLY = re.compile(r"\$wpdb\s*->\s*\w+\s*\(\s*['\"](?:[^'\"$]|\{\$wpdb->\w+\})*['\"]")

# prepare() check: only look in a narrow window (500 chars) to avoid
# matching prepare() in comments or unrelated code above.
_PREPARE_NEARBY = re.compile(r"\$wpdb\s*->\s*prepare\s*\(")


def scan_sql(path, text, project=None) -> list[Finding]:
    findings = []
    lines = text.splitlines()

    # Which variables are tainted and reach a SQL sink?
    flow_results = analyze(
        text, source_file=resolve_source_file(str(path), project), project=project
    )
    tainted_sql_vars: set[str] = {fr.var for fr in flow_results if fr.sink_type == "sql"}
    tainted_sql_lines: dict[str, int] = {
        fr.var: fr.taint_line for fr in flow_results if fr.sink_type == "sql"
    }

    for m in DB_CALLS.finditer(text):
        method = m.group(1)
        line = line_number(text, m.start())

        # Skip matches inside comment lines. DB_CALLS is a plain text scan
        # (not AST-based), so without this a docblock or inline comment
        # merely MENTIONING $wpdb->query() -- e.g. explaining what a
        # method does, or documenting a past fix -- generates a phantom
        # finding, potentially with a fabricated taint chain borrowed from
        # an unrelated real sink elsewhere in the file. Found for real:
        # a comment describing this exact rule's behavior triggered it.
        raw_line = lines[line - 1] if 0 < line <= len(lines) else ""
        if raw_line.lstrip().startswith(("//", "#", "*", "/*")):
            continue

        context = text[m.start() : m.start() + 700]

        # FP guard: call immediately uses prepare() (narrow window only)
        if _PREPARE_NEARBY.search(context):
            continue

        # FP guard: query is a plain string literal (no variable interpolation)
        if _STRING_ONLY.match(context):
            continue

        # Check if any tainted variable appears in the call's context
        involved_var = None
        taint_line = None
        for var in tainted_sql_vars:
            if re.search(rf"\${re.escape(var)}\b", context):
                involved_var = var
                taint_line = tainted_sql_lines.get(var)
                break

        if involved_var:
            severity = "HIGH"
            confidence = 0.82
            flow_type = "taint"
            title = "Tainted input reaches SQL sink without parameterization"
            message = (
                f"${involved_var} originates from user input "
                f"(tainted at line {taint_line}) and is used in "
                f"$wpdb->{method}() without $wpdb->prepare(). "
                f"This is a potential SQL injection."
            )
        else:
            # No proven taint – still worth flagging, but lower confidence
            severity = "MEDIUM"
            confidence = 0.55
            flow_type = None
            taint_line = None
            title = "Database call should be reviewed for parameterization"
            message = (
                "Inspect the complete query and data flow. "
                "Prefer $wpdb->prepare() when values are supplied dynamically."
            )

        findings.append(
            Finding(
                rule_id="WC-SQL-001",
                severity=severity,
                title=title,
                file=str(path),
                line=line,
                message=message,
                owasp="A05:2025-Injection",
                confidence=confidence,
                evidence=snippet(lines, line),
                source=f"${involved_var}" if involved_var else "$wpdb",
                sink=f"$wpdb->{method}()",
                flow_type=flow_type,
                taint_line=taint_line,
            )
        )

    return findings
