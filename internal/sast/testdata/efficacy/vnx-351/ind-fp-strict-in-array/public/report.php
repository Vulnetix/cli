<?php

$allowedReports = [1, 2, 3, 7];
$id = $_GET['report'];
if (!in_array($id, $allowedReports, true)) {
    http_response_code(404);
    exit;
}
$pos = array_search((int) $_GET['page'], [1, 2, 3], true);
