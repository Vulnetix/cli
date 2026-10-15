<?php
$stored = load_token($userId);
if (!hash_equals($stored, $_GET['token'] ?? '')) {
    exit('invalid');
}
if (!in_array($_GET['role'], ['viewer', 'editor'], true)) {
    exit('bad role');
}
if ($_GET['page'] == 'about') {
    include 'about.php';
}
usort($rows, fn($a, $b) => strcmp($a['name'], $b['name']));
if (password_verify($_POST['password'], $row['password_hash'])) {
    login($row);
}
