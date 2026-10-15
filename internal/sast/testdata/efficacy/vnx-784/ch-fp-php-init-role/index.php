<?php
if (!isset($_COOKIE['user_role'])) {
    setcookie('user_role', 'regular_user', time() + 3600, '/');
}
if (isset($_COOKIE['theme']) && $_COOKIE['theme'] === 'dark') {
    $bodyClass = 'dark';
}
