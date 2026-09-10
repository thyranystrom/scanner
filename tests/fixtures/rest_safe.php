<?php
// Fixture: REST route with permission_callback defined.
// Expected findings: none for WC-AUTH-002

register_rest_route('demo/v1', '/thing', [
    'methods'             => 'GET',
    'callback'            => 'demo_callback',
    'permission_callback' => function() {
        return current_user_can('manage_woocommerce');
    },
]);

function demo_callback() {
    return rest_ensure_response(['ok' => true]);
}
