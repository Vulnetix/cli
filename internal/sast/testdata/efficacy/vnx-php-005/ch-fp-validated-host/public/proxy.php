<?php
$url = $_POST['url'];
$host = parse_url($url, PHP_URL_HOST);
if (!in_array($host, ['cdn.example.com', 'img.example.com'], true)) {
    http_response_code(400);
    exit;
}
$body = file_get_contents($url);
