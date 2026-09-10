<?php
// REGRESSION: A hardcoded S3 URL should NOT be flagged as SSRF
function fetch_config() {
    $args = wp_remote_get( 'https://krokedil-settings.s3.eu-north-1.amazonaws.com/config.json' );
    if ( is_wp_error( $args ) ) {
        return null;
    }
    return json_decode( wp_remote_retrieve_body( $args ), true );
}
