<?php
// REGRESSION: Taint chain $a -> $b -> $c -> SQL must be flagged
function process_order() {
    global $wpdb;
    $raw    = $_POST['order_id'];
    $id     = $raw;
    $query  = "SELECT * FROM orders WHERE id = $id";
    $result = $wpdb->get_results( $query );
    return $result;
}
