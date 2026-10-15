<?php
spl_autoload_register(function ($class) {
    $file = __DIR__ . '/' . str_replace('\\', '/', $class) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
$env = getenv('APP_ENV') ?: 'prod';
require __DIR__ . "/../config/$env.php";
