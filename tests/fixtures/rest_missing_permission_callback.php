<?php
// Fixture: REST route without permission_callback.
// Expected findings: WC-AUTH-002

register_rest_route('demo/v1', '/thing', [
    'methods'  => 'GET',
    'callback' => 'demo_callback',
]);

function demo_callback() {
    return rest_ensure_response(['ok' => true]);
}
