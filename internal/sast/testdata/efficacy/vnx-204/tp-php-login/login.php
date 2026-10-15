<?php
$stmt = $pdo->prepare('SELECT id, hash FROM users WHERE email = ?');
$stmt->execute([$_POST['email']]);
$row = $stmt->fetch();
if (!$row) {
~>    $error = "That email is not registered";
} elseif (!password_verify($_POST['password'], $row['hash'])) {
    $error = "Invalid password, please try again";
} else {
    $_SESSION['uid'] = $row['id'];
}
