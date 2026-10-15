<?php
require __DIR__ . '/../bootstrap.php';

$user = trim($_POST['username']);
~>$digest = hash('sha256', $_POST['password']);
$stmt = $pdo->prepare('INSERT INTO users (name, pw) VALUES (?, ?)');
$stmt->execute([$user, $digest]);

function check_login($pdo, $name, $password) {
~>    $hashed = sha1( $password );
    $stmt = $pdo->prepare('SELECT 1 FROM users WHERE name = ? AND pw = ?');
    $stmt->execute([$name, $hashed]);
    return (bool) $stmt->fetchColumn();
}
