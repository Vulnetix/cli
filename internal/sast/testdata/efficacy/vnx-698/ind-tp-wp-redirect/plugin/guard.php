<?php
function maybe_guard() {
    if (!is_user_logged_in()) {
~>        wp_redirect(home_url('/login'));
    }
    update_option('secret_setting', $_POST['v']);
    echo 'saved';
}
