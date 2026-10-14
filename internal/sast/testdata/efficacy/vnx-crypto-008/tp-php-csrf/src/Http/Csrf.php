<?php

function check_csrf($user_token, $session_token) {
~>    if ($user_token !== $session_token) {
        die('CSRF token is incorrect');
    }
}

function verify_webhook($payload, $secret) {
~>    return hash_hmac('sha256', $payload, $secret) == $_SERVER['HTTP_X_HUB_SIGNATURE'];
}
