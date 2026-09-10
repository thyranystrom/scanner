<?php
// Fixture: sanitized before SQL sink (should NOT trigger HIGH)
function get_order() {
    global $wpdb;
    $id = absint($_GET['order_id']);
    $result = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM orders WHERE id = %d", $id)
    );
    return $result;
}
