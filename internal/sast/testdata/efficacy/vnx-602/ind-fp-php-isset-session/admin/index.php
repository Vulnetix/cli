<?php
session_start();

if (!isset($_POST['role'])) {
    $_POST['role'] = 'viewer';
}

if ($_SESSION['role'] !== 'admin') {
    http_response_code(403);
    exit;
}

echo render_admin();
