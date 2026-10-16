<?php
$url = $_GET["url"];
$host = parse_url($url, PHP_URL_HOST);
if (!in_array($host, ["cdn.example.com"], true)) {
    exit("denied");
}
$data = file_get_contents($url);
