<?php
~>if (strpos($_SERVER['QUERY_STRING'], '../') !== false) {
    http_response_code(400);
    exit;
}
$page = $_GET['page'];
include __DIR__ . '/pages/' . $page;
