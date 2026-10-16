<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if ($token === '') {
        http_response_code(400);
        exit;
    }
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        exit('Invalid request');
    }
}
