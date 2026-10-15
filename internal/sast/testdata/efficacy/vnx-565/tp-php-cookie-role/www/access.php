<?php
~>$role = isset($_COOKIE['user_role']) ? $_COOKIE['user_role'] : 'guest';
~>if (isset($_COOKIE["user_id"])) {
~>    $uid = intval($_COOKIE["user_id"]);
    $row = $db->query("SELECT * FROM users WHERE id = " . $uid);
}
~>setcookie('user_role', 'guest', time() + 3600, '/');
