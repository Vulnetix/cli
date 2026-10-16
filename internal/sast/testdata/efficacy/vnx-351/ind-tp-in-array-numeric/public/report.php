<?php

$allowedReports = [1, 2, 3, 7];
$id = $_GET['report'];
~>if (!in_array($id, $allowedReports)) {
    http_response_code(404);
    exit;
}
include __DIR__ . "/reports/{$id}.php";
