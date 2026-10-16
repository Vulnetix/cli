<?php
session_start();

$file = $_POST['file'];
$dir = '/var/www/uploads/';

if (!isset($_SESSION['user'])) {
    http_response_code(401);
    exit;
}

~>if (unlink($dir . $file)) {
    echo "deleted";
}
