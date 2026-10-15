<?php
$redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
$redirect_to = wp_validate_redirect($redirect_to, home_url());
wp_redirect($redirect_to);
exit;
