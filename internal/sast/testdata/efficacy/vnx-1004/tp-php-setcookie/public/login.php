<?php
define('COOKIE_NAME', 'x');
$token = bin2hex(random_bytes(16));
~>setcookie('session_token', $token);
~>setcookie("auth", $token, time() + 3600, "/", "", true, false);
~>setcookie('remember_me', $token, [
    'expires' => time() + 86400,
    'secure' => true,
    'samesite' => 'Lax',
]);
~>ini_set('session.cookie_httponly', 0);
~>session_set_cookie_params(['lifetime' => 0, 'httponly' => false]);
