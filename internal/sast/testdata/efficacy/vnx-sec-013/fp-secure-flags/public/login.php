<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', '1');
setcookie("auth_token", $token, time() + 3600, "/", "", true, true);
setcookie("auth_token", $token, ['expires' => time() + 3600, 'secure' => true, 'httponly' => true]);
