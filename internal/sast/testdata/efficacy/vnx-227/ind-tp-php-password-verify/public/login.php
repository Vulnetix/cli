<?php
session_start();
$stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE email = ?');
$stmt->execute([$_POST['email']]);
$row = $stmt->fetch();
~>password_verify($_POST['password'], $row['password_hash']);
$_SESSION['uid'] = $row['id'];
header('Location: /dashboard');
