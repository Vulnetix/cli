<?php
session_start();
if (empty($_SESSION['is_admin'])) {
~>    header('location: /login.php?next=' . urlencode($_SERVER['REQUEST_URI']));
}
$users = $db->query('SELECT * FROM users')->fetchAll();
foreach ($users as $u) {
    echo htmlspecialchars($u['name']);
}
