<?php
$user = $_POST['user'];
~>$enc = base64_encode($_POST['password']);
$stmt = $pdo->prepare("INSERT INTO users (name, pw) VALUES (?, ?)");
$stmt->execute([$user, $enc]);
