<?php
require 'vendor/autoload.php';

$users = (new MongoDB\Client())->app->users;

$username = (string) ($_POST['username'] ?? '');
$user = $users->findOne(['username' => $username]);

$active = $users->find(['status' => 'active']);

if ($user && password_verify((string) $_POST['password'], $user['hash'])) {
    $_SESSION['uid'] = (string) $user['_id'];
}
