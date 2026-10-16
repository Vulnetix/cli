<?php
session_start();
$token = bin2hex(random_bytes(32));
~>setcookie('session_token', $token, time() + 3600, '/');
header('Location: /dashboard');
