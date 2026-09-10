<?php
// REGRESSION: base64_decode/json_decode wrapping $_GET is deliberate raw-data consumption
function handle_redirect() {
    $messages = json_decode( base64_decode( wp_unslash( $_GET['kec_messages'] ) ), true );
    if ( ! is_array( $messages ) ) {
        return;
    }
}
