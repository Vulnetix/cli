<?php
session_start();
$allowed = ['theme', 'language', 'notifications'];
$name = $_POST['pref'] ?? '';
if (in_array($name, $allowed, true)) {
    $_SESSION['preferences'][$name] = $_POST['value'];
}
