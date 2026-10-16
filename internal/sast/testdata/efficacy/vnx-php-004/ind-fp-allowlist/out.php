<?php
$u = $_GET["url"];
$host = parse_url($u, PHP_URL_HOST);
if (!in_array($host, ["example.com", "www.example.com"], true)) {
    http_response_code(400);
    exit;
}
header("Location: " . $u);
