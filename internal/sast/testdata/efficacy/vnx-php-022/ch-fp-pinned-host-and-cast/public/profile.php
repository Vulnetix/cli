<?php
$id = (int) $_GET['id'];
header('Location: /profile.php?id=' . $id);
exit;

header('Location: https://shop.example.com/products/' . rawurlencode($_GET['slug']));

$allowed = ['/home', '/settings', '/billing'];
$next = $_GET['next'] ?? '/home';
if (!in_array($next, $allowed, true)) {
    $next = '/home';
}
header("Location: $next");
