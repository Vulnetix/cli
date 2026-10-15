<?php
if (!isset($_COOKIE['user_role'])) {
    setcookie('user_role', 'regular_user', time() + 3600, '/');
}
