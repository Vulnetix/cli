<?php
$settings = parse_ini_file(__DIR__ . '/settings.ini');
foreach ($settings as $key => $value) {
    $GLOBALS['cfg_' . $key] = $value;
}
foreach ($_POST as $field => $value) {
    $clean[$field] = htmlspecialchars($value);
}
foreach ($_GET as $k => $v) {
    $GLOBALS['request_log'][] = $k;
}
