<?php
session_start();
require __DIR__ . '/../db.php';

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE email = ?');
    $stmt->execute([$_POST['email']]);
    $row = $stmt->fetch();
    if (!$row) {
~>        $errors[] = 'This email is not registered.';
    } elseif (!password_verify($_POST['password'], $row['password_hash'])) {
        $errors[] = 'The password you entered is wrong.';
    } else {
        $_SESSION['uid'] = $row['id'];
        header('Location: /dashboard');
        exit;
    }
}
