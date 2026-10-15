<?php
$token = bin2hex(random_bytes(32));
store_session($token, $user);
~>setcookie('session_token', $token, ['expires' => time() + 86400 * 90, 'httponly' => true, 'secure' => true]);
header('Location: /dashboard');
