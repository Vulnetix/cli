<?php
$routes = [
    'home'    => 'pages/home.php',
    'about'   => 'pages/about.php',
    'contact' => 'pages/contact.php',
];

$target = $routes[$_GET['p'] ?? 'home'] ?? 'pages/404.php';
include $target;
require $routes[$_GET['p']] ?? 'pages/404.php';
