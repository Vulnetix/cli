<?php
~>ini_set('session.cookie_httponly', 0);
~>ini_set('session.cookie_secure', '0');
~>setcookie("auth_token", $token, time() + 3600, "/", "", false, false);
session_set_cookie_params([
    'lifetime' => 3600,
~>    'httponly' => false,
]);
