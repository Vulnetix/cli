<?php
header('Content-Type: application/json');
try {
    $pdo = new PDO($dsn, $user, $pass);
    $stmt = $pdo->query("SELECT id, name FROM users");
    echo json_encode($stmt->fetchAll());
} catch (\PDOException $ex) {
    http_response_code(500);
~>    echo json_encode(['error' => $ex->getMessage()]);
}
