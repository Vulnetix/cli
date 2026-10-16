<?php
session_start();
session_destroy();

$redirect = $_GET['redirect'] ?? '/';
if (strpos($redirect, 'https://app.example.com/') === 0) {
    header('Location: ' . $redirect);
    exit;
}
header('Location: /');
