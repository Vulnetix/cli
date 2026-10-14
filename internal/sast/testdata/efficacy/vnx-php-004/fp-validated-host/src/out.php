<?php
$url = $_GET["url"];
$allowed = ["docs.example.com", "status.example.com"];
if (!in_array(parse_url($url, PHP_URL_HOST), $allowed, true)) {
    $url = "/";
}
header("Location: " . $url);

$dest = $_POST["dest"];
if (!preg_match("#^/[a-z0-9/_-]*$#i", $dest)) {
    exit;
}
header("Location: " . $dest);
