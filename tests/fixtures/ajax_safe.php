<?php
// Fixture: safe AJAX handler – has nonce check, sanitized input, escaped output.
// Expected findings: none for WC-AUTH-001, WC-INPUT-002, WC-OUTPUT-001

add_action('wp_ajax_test_action', 'test_callback');

function test_callback() {
    check_ajax_referer('test');

    $value = sanitize_text_field($_POST['value']);

    echo esc_html($value);
}
