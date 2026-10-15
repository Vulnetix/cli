<?php
$pages = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$page = $pages[$_GET['p'] ?? 'home'] ?? 'pages/home.php';
include $page;
$routes = require __DIR__ . '/../config/routes.php';
$file = $routes[$_GET['r']] ?? null;
if ($file !== null) {
    require $file;
}
