<?php
require __DIR__ . "/../vendor/autoload.php";
require_once dirname(__DIR__) . "/config/app.php";
include "partials/header.php";
$config = require $configPath;
foreach ($plugins as $plugin) {
    require_once $plugin->bootstrapFile();
}
function load_view($view) {
    include __DIR__ . "/views/" . $view . ".php";
}
