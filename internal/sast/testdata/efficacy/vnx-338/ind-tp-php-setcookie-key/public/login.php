<?php
session_start();

if (check_credentials($_POST['user'], $_POST['pass'])) {
~>    setcookie('remember_token', rand(100000, 999999) . rand(100000, 999999), time() + 86400 * 30, '/', '', true, true);
    header('Location: /dashboard');
    exit;
}
