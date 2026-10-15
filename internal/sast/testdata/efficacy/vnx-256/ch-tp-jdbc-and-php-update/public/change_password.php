<?php
require __DIR__ . '/../bootstrap.php';

$stmt = $pdo->prepare(
~>    "UPDATE users SET password = ? WHERE id = ?"
);
$stmt->execute([$_POST['new_password'], $_SESSION['uid']]);
