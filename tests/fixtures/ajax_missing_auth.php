<?php
// Fixture: AJAX handler missing auth -- no nonce, no capability check.
// Expected findings: WC-AUTH-001, WC-INPUT-002, WC-OUTPUT-001

add_action('wp_ajax_nopriv_test_action', 'test_callback');

function test_callback() {
    $value = $_POST['value'];
    echo $value;
}
