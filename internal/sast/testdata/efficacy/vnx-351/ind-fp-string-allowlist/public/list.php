<?php

$sort = $_GET['sort'] ?? 'name';
if (!in_array($sort, ['name', 'created_at', 'price'])) {
    $sort = 'name';
}
if (in_array('debug', $flags)) {
    enable_debug();
}
$dir = $_GET['dir'] ?? '';
if ($dir == '' || $dir === null) {
    $dir = 'asc';
}
