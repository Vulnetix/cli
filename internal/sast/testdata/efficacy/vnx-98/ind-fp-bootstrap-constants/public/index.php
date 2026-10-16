<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
$config = require __DIR__ . '/../config/app.php';

$theme = $config['theme'] ?? 'default';
include __DIR__ . '/../themes/' . $theme . '/layout.php';

foreach (glob(__DIR__ . '/../routes/*.php') as $routeFile) {
    require $routeFile;
}
