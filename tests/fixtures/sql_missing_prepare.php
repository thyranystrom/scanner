<?php
// Fixture: $wpdb->query() without prepare().
// Expected findings: WC-SQL-001

global $wpdb;

$id = $_GET['id'];
$result = $wpdb->query("SELECT * FROM {$wpdb->prefix}orders WHERE id = $id");
