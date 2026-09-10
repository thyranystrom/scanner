<?php
// REGRESSION: md5() used as a cache key is NOT a security problem
function get_cached_rates() {
    $cache_key = md5( 'exchange_rates_' . date( 'Y-m-d' ) );
    if ( $cached = get_transient( $cache_key ) ) {
        return $cached;
    }
    return null;
}
