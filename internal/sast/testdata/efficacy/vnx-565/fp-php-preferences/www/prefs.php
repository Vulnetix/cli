<?php
$theme = isset($_COOKIE['theme']) ? $_COOKIE['theme'] : 'light';
if (isset($_COOKIE[session_name()])) {
    session_id($_COOKIE[session_name()]);
}
echo "Hello " . htmlspecialchars($_COOKIE['username'] ?? 'guest');
setcookie('theme', 'dark', time() + 3600, '/');
