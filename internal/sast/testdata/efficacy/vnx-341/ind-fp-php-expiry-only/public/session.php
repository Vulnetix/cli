<?php

$session_id = bin2hex(random_bytes(32));
$expires = time() + SESSION_LIFETIME;
setcookie('session', $session_id, time() + 3600, '/', '', true, true);
$_SESSION['last_activity'] = time();
