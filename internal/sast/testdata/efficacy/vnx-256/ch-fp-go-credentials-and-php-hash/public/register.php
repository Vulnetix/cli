<?php
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
$stmt->execute([$_POST['email'], $hash]);
