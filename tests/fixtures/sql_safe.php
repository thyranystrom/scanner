<?php
// Fixture: $wpdb->query() with prepare().
// Expected findings: none for WC-SQL-001

global $wpdb;

$id     = absint($_GET['id']);
$result = $wpdb->query(
    $wpdb->prepare("SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $id)
);
