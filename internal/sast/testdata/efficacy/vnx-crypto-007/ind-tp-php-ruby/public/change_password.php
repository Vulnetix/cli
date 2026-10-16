<?php
require __DIR__ . '/../bootstrap.php';

$salt = bin2hex(random_bytes(8));
~>$hash = sha1($_POST['new_password'] . $salt);
$stmt = $pdo->prepare('UPDATE users SET pw = ?, salt = ? WHERE id = ?');
$stmt->execute([$hash, $salt, $_SESSION['uid']]);
