<?php
ini_set('session.cookie_httponly', '1');
session_start();

setcookie('auth_token', $token, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);

setcookie('theme', 'dark', time() + 86400, '/');
