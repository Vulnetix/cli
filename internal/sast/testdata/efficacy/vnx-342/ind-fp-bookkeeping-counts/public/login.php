<?php
session_start();

if (!check_password($_POST['user'], $_POST['pass'])) {
    $_SESSION['login_attempts']++;
    $tokenCount = count($_SESSION['tokens'] ?? []);
    $tokenCount++;
    header('Location: /login?error=1');
    exit;
}
