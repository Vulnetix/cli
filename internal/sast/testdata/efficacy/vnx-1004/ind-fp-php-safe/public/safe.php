<?php
setcookie('session_token', $token, time() + 3600, '/', '', true, true);
setcookie('auth', $token, ['expires' => time() + 60, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
setcookie('locale', 'en');
// setcookie('session_token', $token);
