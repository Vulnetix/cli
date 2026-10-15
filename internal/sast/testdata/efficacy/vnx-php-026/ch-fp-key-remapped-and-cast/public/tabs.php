<?php
const TAB_KEYS = ['home' => 'tab_home', 'billing' => 'tab_billing'];

$tab = $_GET['tab'] ?? 'home';
$tab = TAB_KEYS[$tab] ?? 'tab_home';
$_SESSION[$tab] = true;

$slot = (int) $_POST['slot'];
$_SESSION[$slot] = $_POST['label'];

$mode = $_GET['mode'] ?? '';
if (!in_array($mode, ['grid', 'list'], true)) {
    $mode = 'grid';
}
$_SESSION[$mode] = time();
