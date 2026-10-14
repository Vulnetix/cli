<?php
$url = $_GET["url"];
$host = parse_url($url, PHP_URL_HOST);
if (!in_array($host, ["cdn.example.com", "img.example.com"], true)) {
    http_response_code(400);
    exit;
}
$img = file_get_contents($url);

$feed = $_POST["feed"];
if (!preg_match("#^https://feeds\.example\.com/#", $feed)) {
    exit;
}
$xml = file_get_contents($feed);
