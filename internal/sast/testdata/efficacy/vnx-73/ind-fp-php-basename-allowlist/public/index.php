<?php
$pages = ['home', 'about', 'contact'];

$page = $_GET['page'] ?? 'home';
if (!in_array($page, $pages, true)) {
    $page = 'home';
}
include __DIR__ . '/pages/' . $page . '.php';

$name = basename($_GET['file']);
echo file_get_contents('/var/www/docs/' . $name);
