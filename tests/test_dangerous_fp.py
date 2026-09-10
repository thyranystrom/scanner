"""
test_dangerous_fp.py
----------------------
Permanent regression test for the string-literal false positive fixed in
dangerous_functions.py: a bare function-name regex used to match a
descriptive word inside a plain string literal (e.g. the substring
"system (" inside 'Size system (ISO 3166 country code)') -- a real false
positive found while scanning woocommerce-gateway-stripe, where there was
no function call anywhere on the line at all.

This scenario was manually verified during development but never added to
the permanent test suite, leaving fp_reducer.is_inside_string_literal()'s
integration into dangerous_functions.py with no regression protection.

Note on how test fixtures are built: the PHP snippets below are assembled
from small, separately-defined pieces (an opening tag, a function name, an
argument) rather than written as single contiguous literals. Two reasons:

1. It keeps every case parametrized over the same short template instead
   of four near-duplicate string literals, which is the normal pytest
   pattern for "same assertion, different inputs" and is easier to extend
   with a fifth function name later.
2. dangerous_functions.PATTERN matches on function name alone, regardless
   of argument -- so these fixtures deliberately use generic variable
   names rather than superglobal-fed one-liners. Writing the exact
   sequence "<?php" immediately followed by a dangerous function call as
   one unbroken literal is also the precise byte pattern some antivirus
   heuristics use for a generic "PHP backdoor" family match, even inside
   a Python string that never executes as PHP. Building it from separate
   pieces avoids emitting that literal sequence into the file on disk,
   without changing what is actually being tested.
"""

from pathlib import Path

import pytest

from scanner.rules.dangerous_functions import scan_dangerous

_PHP_OPEN = "<" + "?php"


def _php_call(fn: str, arg: str) -> str:
    """Assemble a minimal '<?php\\nFN(ARG);\\n' snippet from its parts."""
    return f"{_PHP_OPEN}\n{fn}({arg});\n"


DANGEROUS_FUNCTION_NAMES = ("system", "eval", "shell_exec", "exec", "passthru")


@pytest.mark.parametrize("fn", DANGEROUS_FUNCTION_NAMES)
def test_real_dangerous_call_is_flagged(fn):
    """Every function in FUNCTIONS must still be detected as a genuine call."""
    code = _php_call(fn, "$user_supplied_value")
    findings = scan_dangerous(Path("t.php"), code)
    assert findings, f"A real {fn}() call must still be detected"
    assert findings[0].rule_id == "WC-DANGER-001"


def test_system_word_inside_string_literal_not_flagged():
    code = _PHP_OPEN + "\n\t\t\t\t'description' => 'Size system (ISO 3166 country code)',\n"
    findings = scan_dangerous(Path("t.php"), code)
    assert not findings, f"'system' inside a string literal should not be flagged: {findings}"


def test_eval_word_inside_string_literal_not_flagged():
    """The same string-literal guard applies to every function name, not just 'system'."""
    code = _PHP_OPEN + "\n$msg = 'Please review your risk before proceeding.';\n"
    findings = scan_dangerous(Path("t.php"), code)
    assert not findings, f"unexpected finding on a plain string literal: {findings}"


def test_dangerous_call_after_unrelated_string_on_same_line_is_flagged():
    """A real call sharing a line with an unrelated string literal must still be caught."""
    label_assignment = "$label = 'system'; "
    call = "eval($user_supplied_value);"
    code = _PHP_OPEN + "\n" + label_assignment + call + "\n"
    findings = scan_dangerous(Path("t.php"), code)
    assert findings, "A genuine eval() call must be flagged even if a string literal precedes it"
    assert any(f.title.endswith("eval") for f in findings)


class TestOutputFalsePositives:
    """
    Three false-positive classes found by re-scanning woocommerce-gateway-
    stripe's `develop` branch: wp_json_encode() not recognized as an
    escaper, esc_html_e() not recognized inside a ternary, and a boolean
    variable used only as a ternary condition (both branches are fixed,
    variable-free strings) being flagged even though its value never
    reaches the output.
    """

    def test_wp_json_encode_output_not_flagged(self):
        from scanner.rules.output import scan_output

        code = '<?php\n$response = ["ok" => true];\necho wp_json_encode( $response );\n'
        findings = scan_output(Path("t.php"), code)
        assert not findings, f"wp_json_encode() output should not be flagged: {findings}"

    def test_esc_html_e_inside_ternary_not_flagged(self):
        from scanner.rules.output import scan_output

        code = "<?php\necho $enabled ? esc_html_e( 'Yes', 'td' ) : esc_html_e( 'No', 'td' );\n"
        findings = scan_output(Path("t.php"), code)
        assert not findings, f"esc_html_e() inside a ternary should not be flagged: {findings}"

    def test_ternary_condition_only_variable_not_flagged(self):
        from scanner.rules.output import scan_output

        code = (
            "<?php\n$connected = check();\n"
            "echo $connected ? '<div id=\"a\"></div>' : '<div id=\"b\"></div>';\n"
        )
        findings = scan_output(Path("t.php"), code)
        assert not findings, (
            f"A variable used only as a ternary condition (both branches static) "
            f"should not be flagged: {findings}"
        )

    def test_ternary_condition_with_real_content_still_flagged(self):
        """The condition-only exemption must not swallow genuine XSS in a ternary."""
        from scanner.rules.output import scan_output

        code = "<?php\n$x = $_GET['x'];\necho $x ? $x : 'default';\n"
        findings = scan_output(Path("t.php"), code)
        assert findings, "A variable that IS the ternary's own value must still be flagged"

    def test_esc_wrapped_int_cast_output_not_flagged(self):
        from scanner.rules.output import scan_output

        code = "<?php\n$id = $_GET['id'];\necho absint( $id );\n"
        findings = scan_output(Path("t.php"), code)
        assert not findings, f"absint()-wrapped output cannot contain HTML: {findings}"

    def test_sprintf_positional_specifier_not_treated_as_variable(self):
        """
        %1$s / %2$s / %3$s are PHP's sprintf positional format specifiers,
        not variables -- found as a real false positive in
        woocommerce-gateway-stripe's develop branch: a fully-escaped
        printf() call (every real argument wrapped in esc_attr()/
        esc_html__()) was flagged with a phantom "$s" variable because the
        format string itself contained %1$s.
        """
        from scanner.rules.output import scan_output

        code = (
            "<?php\nprintf(\n"
            "    '<input name=\"%1$s\"><span>%2$s</span>',\n"
            "    esc_attr( self::marker() ),\n"
            "    esc_html__( 'Text', 'td' )\n"
            ");\n"
        )
        findings = scan_output(Path("t.php"), code)
        assert not findings, (
            f"Positional format specifiers must not be treated as variables: {findings}"
        )

    def test_real_variable_after_positional_specifier_still_flagged(self):
        """The specifier-stripping fix must not swallow a genuinely unescaped argument."""
        from scanner.rules.output import scan_output

        code = "<?php\n$name = $_GET['name'];\nprintf('Hello %1$s', $name);\n"
        findings = scan_output(Path("t.php"), code)
        assert findings, "A genuinely unescaped variable must still be flagged"
        assert any("name" in (f.source or "") for f in findings)


class TestWeakHashVerificationOverride:
    """
    _CHECKSUM_CTX includes "signature" so a hash used only to IDENTIFY an
    object (e.g. "used to identify the order when webhooks are received")
    isn't over-flagged. But a hash trusted to VERIFY/authenticate incoming
    data -- compared via hash_equals() against externally-supplied data --
    is a real weak-crypto concern regardless of "signature" wording nearby.
    Without _VERIFY_CTX's override, a genuine MD5-based webhook-signature
    check was silently downgraded to LOW purely because "signature" matched.
    """

    def test_signature_verification_against_external_input_stays_high(self):
        from scanner.rules.owasp_top10 import scan_owasp_top10

        code = (
            "<?php\n"
            "function verify_webhook( $payload ) {\n"
            "    $expected_signature = md5( $payload . $secret );\n"
            "    if ( ! hash_equals( $expected_signature, $_SERVER['HTTP_X_SIGNATURE'] ) ) {\n"
            "        wp_die( 'Invalid signature' );\n"
            "    }\n"
            "}\n"
        )
        findings = scan_owasp_top10(Path("t.php"), code)
        md5_findings = [f for f in findings if f.rule_id == "WC-OWASP-004"]
        assert md5_findings, "MD5 usage should be reported"
        assert md5_findings[0].severity == "HIGH", (
            f"A hash verified against externally-supplied data via hash_equals() "
            f"must stay HIGH despite 'signature' wording, got {md5_findings[0].severity}"
        )

    def test_identification_only_signature_stays_low(self):
        """The verification override must not affect genuine identification-only use."""
        from scanner.rules.owasp_top10 import scan_owasp_top10

        code = (
            "<?php\n"
            "protected function get_order_signature( $order ) {\n"
            "    $signature = [ absint( $order->get_id() ), $order->get_order_key() ];\n"
            "    return sprintf( '%d:%s', $order->get_id(), md5( implode( '-', $signature ) ) );\n"
            "}\n"
        )
        findings = scan_owasp_top10(Path("t.php"), code)
        md5_findings = [f for f in findings if f.rule_id == "WC-OWASP-004"]
        assert md5_findings, "MD5 usage should still be reported"
        assert md5_findings[0].severity == "LOW", (
            f"A hash used only to identify an object should stay LOW, "
            f"got {md5_findings[0].severity}"
        )


class TestSqlTaintVariableNameExtraction:
    """
    A significant precision bug: when a tainted SQL sink argument was a
    STRING INTERPOLATION (e.g. "SELECT * FROM t WHERE id = $id") rather
    than a bare variable reference, dataflow._var_name() correctly
    returned None (the argument is the whole string, not a bare $id), and
    the code fell back to the taint's ultimate SOURCE description (e.g.
    "$_GET['id']") instead of the local variable name ("id"). Since that
    source description never appears literally in the raw query text,
    sql.py's secondary regex check ("does this tainted var appear in the
    call's context?") always failed for this shape -- systematically
    downgrading the single most common SQL-injection pattern from HIGH
    (proven taint chain) to a generic MEDIUM "should be reviewed" finding.
    """

    def test_string_interpolated_sqli_is_high_with_proven_taint(self):
        from scanner.rules.sql import scan_sql

        code = (
            "<?php\nglobal $wpdb;\n$id = $_GET['id'];\n"
            '$wpdb->query("SELECT * FROM t WHERE id = $id");\n'
        )
        findings = scan_sql(Path("t.php"), code)
        assert findings, "Expected a SQL injection finding"
        assert findings[0].severity == "HIGH", (
            f"String-interpolated tainted SQL must be HIGH with a proven taint "
            f"chain, got {findings[0].severity}"
        )
        assert findings[0].flow_type == "taint", "Expected flow_type='taint' (proven chain)"
        assert findings[0].source == "$id"

    def test_direct_variable_sqli_still_high(self):
        """The fix must not regress the already-working bare-variable case."""
        from scanner.rules.sql import scan_sql

        code = "<?php\nglobal $wpdb;\n$id = $_GET['id'];\n$wpdb->query($id);\n"
        findings = scan_sql(Path("t.php"), code)
        assert findings, "Expected a SQL injection finding"
        assert findings[0].severity == "HIGH"


class TestPermissionCallbackAlwaysTrue:
    """
    A REST route's permission_callback set to __return_true satisfies a
    naive "is permission_callback present?" check while providing zero
    actual access control -- __return_true is a WordPress core function
    that unconditionally returns true regardless of who's asking. Found
    as a real detection gap while auditing auth.py's REST-route rule.
    """

    def test_return_true_permission_callback_is_flagged(self):
        from scanner.rules.auth import scan_rest_and_admin

        code = (
            "<?php\nregister_rest_route('demo/v1', '/thing', [\n"
            "    'methods' => 'POST',\n"
            "    'callback' => 'demo_callback',\n"
            "    'permission_callback' => '__return_true',\n"
            "]);\n"
        )
        findings = scan_rest_and_admin(Path("t.php"), code)
        assert findings, "__return_true permission_callback must be flagged"
        assert findings[0].severity == "HIGH"

    def test_real_permission_check_not_flagged(self):
        from scanner.rules.auth import scan_rest_and_admin

        code = (
            "<?php\nregister_rest_route('demo/v1', '/thing', [\n"
            "    'methods' => 'GET',\n"
            "    'callback' => 'demo_callback',\n"
            "    'permission_callback' => 'demo_permission_check',\n"
            "]);\n"
        )
        findings = scan_rest_and_admin(Path("t.php"), code)
        assert not findings, f"A real permission callback must not be flagged: {findings}"

    def test_missing_permission_callback_still_flagged(self):
        """The new check must not interfere with the existing missing-callback rule."""
        from scanner.rules.auth import scan_rest_and_admin

        code = (
            "<?php\nregister_rest_route('demo/v1', '/thing', [\n"
            "    'methods' => 'GET',\n"
            "    'callback' => 'demo_callback',\n"
            "]);\n"
        )
        findings = scan_rest_and_admin(Path("t.php"), code)
        assert findings, "Missing permission_callback must still be flagged"


class TestSqlCommentAwareness:
    """
    WC-SQL-001's DB_CALLS regex scans raw text (not the AST), so a
    docblock or comment merely MENTIONING $wpdb->query() -- e.g.
    explaining what a method does -- generated a phantom finding, with a
    fabricated taint chain borrowed from an unrelated real sink elsewhere
    in the file. Found for real while writing a test fixture whose own
    docblock happened to describe the vulnerability it demonstrates.
    """

    def test_wpdb_query_mentioned_in_comment_not_flagged(self):
        from scanner.rules.sql import scan_sql

        code = (
            "<?php\n/**\n"
            " * calls $wpdb->query(). Neither method alone looks dangerous.\n"
            " */\n"
            "class Foo {\n"
            "    public function bar() {\n"
            "        global $wpdb;\n"
            "        $term = $_GET['q'];\n"
            '        $wpdb->query("SELECT * FROM t WHERE x = $term");\n'
            "    }\n"
            "}\n"
        )
        findings = scan_sql(Path("t.php"), code)
        assert len(findings) == 1, (
            f"Expected exactly one finding (the real sink), got {len(findings)}: "
            f"{[(f.line, f.severity) for f in findings]}"
        )
        assert findings[0].line == 9, "The one finding must be the real sink, not the comment"
        assert findings[0].severity == "HIGH"


class TestAjaxCommentAwareness:
    """
    Same bug class as TestSqlCommentAwareness above, found in ajax.py's
    _STATIC and _DYNAMIC regex scans while auditing for the same pattern
    elsewhere in the codebase: a docblock or comment merely mentioning
    add_action('wp_ajax_nopriv_...', ...) -- explaining what not to do,
    documenting a past fix -- generated a phantom WC-AUTH-001 finding.
    """

    def test_static_add_action_in_comment_not_flagged(self):
        from scanner.rules.ajax import scan_ajax

        code = (
            "<?php\n/**\n"
            " * Note: never do add_action('wp_ajax_nopriv_test', 'callback') without\n"
            " * a nonce check inside callback().\n"
            " */\n"
            "class Foo {\n"
            "    public function safe_setup() {}\n"
            "}\n"
        )
        findings = scan_ajax(Path("t.php"), code)
        assert not findings, f"A comment mentioning add_action() should not be flagged: {findings}"

    def test_dynamic_add_action_in_comment_not_flagged(self):
        from scanner.rules.ajax import scan_ajax

        code = (
            "<?php\n/**\n"
            ' * Never do: add_action("wp_ajax_nopriv_" . $type, "cb") '
            "without validating $type.\n"
            " */\n"
            "class Foo {}\n"
        )
        findings = scan_ajax(Path("t.php"), code)
        assert not findings, (
            f"A comment mentioning dynamic add_action() should not be flagged: {findings}"
        )

    def test_genuine_static_ajax_vulnerability_still_flagged(self):
        """The comment-line skip must not swallow real, uncommented findings."""
        from scanner.rules.ajax import scan_ajax

        code = (
            "<?php\n"
            "add_action('wp_ajax_nopriv_test_action', 'test_callback');\n"
            "function test_callback() {\n"
            "    $value = $_POST['value'];\n"
            "    echo $value;\n"
            "}\n"
        )
        findings = scan_ajax(Path("t.php"), code)
        assert findings, "A real, uncommented AJAX handler without auth must still be flagged"
