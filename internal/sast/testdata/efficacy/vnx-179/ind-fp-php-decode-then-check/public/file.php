<?php
$name = rawurldecode($_GET['name'] ?? '');
if (strpos($name, '..') !== false || strpos($name, '/') !== false) {
    http_response_code(400);
    exit('Invalid file name');
}
readfile(__DIR__ . '/files/' . $name);
