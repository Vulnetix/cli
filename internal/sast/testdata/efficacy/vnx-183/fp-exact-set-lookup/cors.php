<?php

$allowedOrigins = ['https://acme.com', 'https://app.acme.com'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
}
if (str_starts_with($origin, 'https://acme.com/')) {
    header('Vary: Origin');
}
