<?php
session_start();

$is_admin = false;
$theme = 'default';

$name = $_GET['pref'];
~>$$name = $_GET['value'];

if ($is_admin) {
    include __DIR__ . '/../admin/panel.php';
}

$key = $_POST['key'];
~>echo htmlspecialchars((string) ${$key});
