<?php
// Fixture: tainted variable reaches SQL sink (should be HIGH)
function get_order() {
    global $wpdb;
    $id = $_GET['order_id'];
    $result = $wpdb->get_results("SELECT * FROM orders WHERE id = $id");
    return $result;
}
