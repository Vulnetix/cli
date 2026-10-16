<?php
require __DIR__ . '/../bootstrap.php';

~>$userId = $_COOKIE['user_id'] ?? null;
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$userId]);
$user = $stmt->fetch();

if (!$user) {
    header('Location: /login.php');
    exit;
}

~>setcookie('user_id', (string) $user['id'], time() + 86400 * 30, '/', '', true, true);
