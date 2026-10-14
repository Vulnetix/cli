<?php
session_start();

$allowed = ['theme', 'language', 'notifications'];
$pref = $_POST['pref'] ?? '';
if (in_array($pref, $allowed, true)) {
    $_SESSION[$pref] = $_POST['value'];
}

$opt = $_GET['opt'];
if (!array_key_exists($opt, PREF_DEFAULTS)) {
    exit;
}
$_SESSION[$opt] = $_GET['v'];

$mode = $_GET['mode'];
$mode = 'compact';
$_SESSION[$mode] = 1;

if (in_array($_GET['tab'], ['a', 'b'], true)) {
    $_SESSION[$_GET['tab']] = 'open';
}

foreach ($_POST as $k => $v) {
    if (!in_array($k, $allowed, true)) {
        continue;
    }
    $_SESSION[$k] = $v;
}
