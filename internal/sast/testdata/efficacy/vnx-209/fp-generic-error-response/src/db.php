<?php
$conn = mysqli_connect($host, $user, $pass, $db);
if (!$conn) {
    error_log("Connection failed: " . mysqli_connect_error());
    die("Service unavailable");
}
if (!$conn->query($sql)) {
    error_log($conn->error);
    echo "Something went wrong";
}
try {
    $pdo = new PDO($dsn, $user, $pass);
} catch (PDOException $e) {
    error_log($e->getMessage());
    http_response_code(500);
    exit("Database unavailable");
}
ini_set('display_errors', '0');
ini_set('log_errors', '1');
