<?php
// Fixture: superglobal passed to wp_verify_nonce – should NOT fire (v0.6 FP)
function verify() {
    if (!wp_verify_nonce($_POST['_wpnonce'], 'my_action')) {
        wp_die('invalid');
    }
}
