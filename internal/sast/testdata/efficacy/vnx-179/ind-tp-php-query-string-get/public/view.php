<?php
$qs = $_SERVER['QUERY_STRING'];
~>if (strpos($qs, '..') !== false) {
    http_response_code(400);
    exit('Invalid request');
}
$page = $_GET['page'];
include __DIR__ . '/pages/' . $page . '.php';
