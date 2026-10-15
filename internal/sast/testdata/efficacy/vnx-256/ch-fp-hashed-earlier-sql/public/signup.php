<?php
$pw = password_hash($_POST['password'], PASSWORD_ARGON2ID);
$stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
$stmt->execute([$_POST['email'], $pw]);
