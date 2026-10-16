<?php
require __DIR__ . '/../bootstrap.php';

session_start();
$is_admin = false;

~>extract($_POST);

$stmt = $pdo->prepare('UPDATE profiles SET display_name = ?, bio = ? WHERE user_id = ?');
$stmt->execute([$display_name, $bio, $_SESSION['uid']]);
if ($is_admin) {
    header('Location: /admin');
    exit;
}
header('Location: /profile');
