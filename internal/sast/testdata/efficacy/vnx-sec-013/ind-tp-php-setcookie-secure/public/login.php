<?php
$sid = bin2hex(random_bytes(16));
~>setcookie('session_id', $sid, time() + 3600, '/', '', false, true);
header('Location: /dashboard');
