<?php
$conn = mysqli_connect($host, $user, $pass, $db);
if (!$conn) {
~>    die("Connection failed: " . mysqli_connect_error());
}

$result = mysqli_query($conn, $query)
~>    or die('<pre>' . mysqli_error($conn) . '</pre>');

$link = new mysqli($host, $user, $pass, $db);
if ($link->connect_error) {
~>    die("Connect error: " . $link->connect_error);
}
if (!$link->query($sql)) {
~>    echo "Query failed: " . $link->error;
}

try {
    $pdo = new PDO($dsn, $user, $pass);
} catch (PDOException $e) {
~>    die($e->getMessage());
}

try {
    run();
} catch (Exception $ex) {
~>    echo $ex->getTraceAsString();
}

~>ini_set('display_errors', '1');
