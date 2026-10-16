<?php

$config = json_decode(file_get_contents(__DIR__ . '/../config/app.json'), true);
if ($config['env'] == 'production') {
    ini_set('display_errors', '0');
}
$input = json_decode(file_get_contents('php://input'), true);
if ($input['mode'] === 'dry-run') {
    define('DRY_RUN', true);
}
if ($input['name'] == null) {
    exit('name required');
}
