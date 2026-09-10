<?php
add_action( 'wp_ajax_ok', array( $this, 'handler' ) );
public function handler() {
    $this->guard();
    update_option( 'x', 1 );
}
private function guard() {
    check_ajax_referer( 'ok' );
}
