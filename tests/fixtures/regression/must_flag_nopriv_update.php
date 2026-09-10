<?php
add_action( 'wp_ajax_nopriv_evil', array( $this, 'evil' ) );
public function evil() {
    $v = $_POST['v'];
    update_option( 'blogname', $v );
}
