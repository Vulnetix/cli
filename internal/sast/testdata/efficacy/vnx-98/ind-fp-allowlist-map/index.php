<?php
$routes = [
    'home'    => 'pages/home.php',
    'about'   => 'pages/about.php',
    'contact' => 'pages/contact.php',
];

$page = $_GET['page'] ?? 'home';
if (!array_key_exists($page, $routes)) {
    http_response_code(404);
    include __DIR__ . '/pages/404.php';
    exit;
}
include __DIR__ . '/' . $routes[$page];

$section = $_GET['section'] ?? 'intro';
if (!preg_match('/^[a-z]{1,20}$/', $section)) {
    exit('bad section');
}
include __DIR__ . "/sections/{$section}.php";
