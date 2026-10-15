<?php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) {
    $page = 'home';
}
include __DIR__ . '/pages/' . $page . '.php';

$name = basename($_GET['file']);
readfile(__DIR__ . '/downloads/' . $name);
