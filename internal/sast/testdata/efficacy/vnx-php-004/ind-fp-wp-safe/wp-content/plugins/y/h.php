<?php
wp_safe_redirect( $_POST["redirect_to"] );
$dest = wp_validate_redirect( $_GET["to"], home_url() );
wp_redirect( $dest );
