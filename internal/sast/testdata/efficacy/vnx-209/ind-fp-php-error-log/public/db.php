<?php
ini_set('display_errors', '0');
ini_set('log_errors', '1');

$conn = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if (!$conn) {
    error_log('Database connection failed: ' . mysqli_connect_error());
    http_response_code(503);
    die('Service temporarily unavailable');
}
