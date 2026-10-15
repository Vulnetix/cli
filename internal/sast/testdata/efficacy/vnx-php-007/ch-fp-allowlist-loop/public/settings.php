<?php
$allowed = ['theme', 'lang'];
foreach ($allowed as $key) {
    if (isset($_POST[$key])) {
        $$key = $_POST[$key];
    }
}
foreach ($_POST as $key => $value) {
    $data[$key] = trim($value);
}
$GLOBALS['config'] = require __DIR__ . '/config.php';
