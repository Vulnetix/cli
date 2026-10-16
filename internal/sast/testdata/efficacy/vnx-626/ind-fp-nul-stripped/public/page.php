<?php
$page = str_replace(chr(0), '', $_GET['page'] ?? 'home');
if (!preg_match('/^[a-zA-Z0-9_\-]+$/', $page)) {
    die('Invalid page name');
}
include(__DIR__ . '/pages/' . $page . '.php');
