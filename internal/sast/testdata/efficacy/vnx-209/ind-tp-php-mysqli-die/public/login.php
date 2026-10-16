<?php
require __DIR__ . '/../config.php';

$conn = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if (!$conn) {
~>    die('Database connection failed: ' . mysqli_connect_error());
}

$stmt = mysqli_prepare($conn, 'SELECT id, password_hash FROM users WHERE email = ?');
mysqli_stmt_bind_param($stmt, 's', $_POST['email']);
if (!mysqli_stmt_execute($stmt)) {
~>    echo "Query error: " . mysqli_error($conn);
    exit;
}
