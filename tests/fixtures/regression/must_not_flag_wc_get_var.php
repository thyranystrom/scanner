<?php
// REGRESSION: wc_get_var() is a WooCommerce sanitizer -- should NOT flag WC-INPUT
function handle_sign_in() {
    $id_token = wc_get_var( $_POST['id_token'] );
    if ( empty( $id_token ) ) {
        wp_send_json_error( 'missing parameters' );
    }
}
