<?php
/*
 * Plugin Name: Shortlinks
 */

function shortlinks_handle() {
	if ( isset( $_REQUEST['redirect_to'] ) ) {
~>		wp_redirect( $_REQUEST['redirect_to'] );
		exit;
	}
}
add_action( 'template_redirect', 'shortlinks_handle' );
