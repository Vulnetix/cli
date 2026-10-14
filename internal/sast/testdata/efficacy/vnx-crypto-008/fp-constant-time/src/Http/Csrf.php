<?php

function check_csrf($user_token, $session_token) {
    if (!hash_equals($session_token, $user_token)) {
        die('CSRF token is incorrect');
    }
    if ($user_token == '') {
        return false;
    }
}
