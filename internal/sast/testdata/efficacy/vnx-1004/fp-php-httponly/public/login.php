<?php
$token = bin2hex(random_bytes(16));
setcookie('session_token', $token, time() + 3600, '/', '', true, true);
setcookie('auth', $token, ['expires' => time() + 3600, 'secure' => true, 'httponly' => true]);
setcookie('lang', 'en');
setcookie('session_token', '', time() - 3600);
setcookie('security', $level, 0, '/', '', false, $httponly);
ini_set('session.cookie_httponly', 1);
// setcookie('session_token', $token);
echo "setcookie('auth', \$t)";
