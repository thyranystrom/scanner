"""
sanitizers.py
-------------
Canonical list of WordPress/WooCommerce sanitization functions.

Imported by dataflow.py, input.py, and output.py so that every rule module
shares exactly the same definition of what counts as "sanitized." Before
this module existed, each rule file kept its own partial copy of this list,
and the three copies drifted out of sync over time — a function recognized
as a sanitizer by one rule but not another produced inconsistent, confusing
results for the same line of code.

Additional WooCommerce/WordPress-specific sanitizers:
  - wc_get_var          — WooCommerce's get_var() with an optional fallback
  - wc_sanitize_*       — WooCommerce-specific sanitizers
  - map_deep            — WordPress's recursive sanitizer
  - rest_sanitize_*     — REST API sanitizers
  - number_format_i18n  — always returns a formatted string, never user-controlled
  - rawurlencode/urlencode — encode data, reducing XSS risk

Additional output-safe escaping functions:
  - json_encode / wp_json_encode — genuine false positive found while
    scanning woocommerce-gateway-stripe: `echo wp_json_encode($response);`
    at the end of an AJAX handler is the standard, correct WordPress
    pattern for returning a JSON response, and JSON string-encoding
    already escapes the characters that would otherwise enable XSS.
"""

# Functions that fully sanitize their argument: if a call to one of these
# wraps a variable, that variable is treated as clean at that point.
SANITIZERS: frozenset[str] = frozenset(
    {
        # ── WordPress core ────────────────────────────────────────────────
        "sanitize_text_field",
        "sanitize_textarea_field",
        "sanitize_key",
        "sanitize_email",
        "sanitize_url",
        "sanitize_file_name",
        "sanitize_html_class",
        "sanitize_title",
        "sanitize_title_with_dashes",
        "sanitize_user",
        "sanitize_meta",
        "sanitize_option",
        "sanitize_mime_type",
        "map_deep",
        # ── Escaping (sanitizes for output context) ─────────────────────────
        "esc_html",
        "esc_attr",
        "esc_js",
        "esc_url",
        "esc_url_raw",
        "esc_textarea",
        "esc_sql",
        "wp_kses",
        "wp_kses_post",
        "wp_kses_allowed_html",
        # ── Type casting ───────────────────────────────────────────────────
        "absint",
        "intval",
        "floatval",
        "boolval",
        "strval",
        # ── PHP built-ins that reduce risk ─────────────────────────────────
        "htmlspecialchars",
        "htmlentities",
        "strip_tags",
        "addslashes",
        "filter_input",
        "filter_var",
        "preg_quote",
        "number_format",
        "number_format_i18n",
        "rawurlencode",
        "urlencode",
        "json_encode",  # escapes <, >, &, quotes within its string encoding
        "wp_json_encode",  # WordPress's json_encode() wrapper -- same guarantee
        # ── WooCommerce-specific ─────────────────────────────────────────────
        "wc_clean",  # alias for sanitize_text_field with stripslashes
        "wc_get_var",  # get_var($var, $default) — returns a type-checked value
        "wc_sanitize_order_id",
        "wc_format_decimal",
        "wc_stock_amount",
        "wc_trim_string",
        # ── WordPress DB layer ───────────────────────────────────────────────
        "prepare",  # $wpdb->prepare()
        "esc_like",  # $wpdb->esc_like()
        # ── Partial (reduces risk but does not fully sanitize) ──────────────
        # Handled separately as PARTIAL_SANITIZERS in dataflow.py.
        # "wp_unslash" is deliberately NOT included here.
    }
)

# REST API sanitizers (used in permission callbacks, argument schemas, etc.)
REST_SANITIZERS: frozenset[str] = frozenset(
    {
        "rest_sanitize_boolean",
        "rest_sanitize_integer",
        "rest_sanitize_array",
        "rest_sanitize_object",
        "rest_sanitize_hex_color",
        "rest_sanitize_textarea_field",
        "rest_sanitize_request_arg",
    }
)

ALL_SANITIZERS: frozenset[str] = SANITIZERS | REST_SANITIZERS

# Subset of ALL_SANITIZERS that is safe specifically as OUTPUT escaping --
# i.e. wrapping a variable in one of these makes it safe to echo/print
# regardless of surrounding HTML context. This is intentionally narrower
# than ALL_SANITIZERS: functions like sanitize_text_field() belong in the
# general sanitizer list (they're the correct thing to do on the way IN
# from user input) but don't give the same html-entity-encoding guarantee
# esc_html() does, so they should not, on their own, silence an XSS
# finding at an output sink. Type-casting functions (absint, intval, ...)
# are included because their result can never contain HTML by
# construction, regardless of context.
OUTPUT_SAFE: frozenset[str] = frozenset(
    {
        "esc_html",
        "esc_html_e",  # echoes the escaped string directly (WordPress i18n convention)
        "esc_attr",
        "esc_attr_e",
        "esc_js",
        "esc_url",
        "esc_url_raw",
        "esc_textarea",
        "esc_sql",
        "wp_kses",
        "wp_kses_post",
        "wp_kses_allowed_html",
        "htmlspecialchars",
        "htmlentities",
        "json_encode",
        "wp_json_encode",
        "absint",
        "intval",
        "floatval",
        "boolval",
    }
)
