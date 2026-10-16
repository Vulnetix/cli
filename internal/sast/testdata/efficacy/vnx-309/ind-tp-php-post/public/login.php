<?php
require __DIR__ . '/../bootstrap.php';

$stmt = $pdo->prepare('SELECT id, password FROM users WHERE email = ?');
$stmt->execute([$_POST['email']]);
$row = $stmt->fetch();

~>if ($row && $row['password'] == $_POST['password']) {
    $_SESSION['user_id'] = $row['id'];
    header('Location: /dashboard');
    exit;
}
http_response_code(401);
