<?php
require_once __DIR__ . '/auth.php';
require_admin();

$module = filter_input(INPUT_GET, 'module', FILTER_UNSAFE_RAW);
if ($module === null) {
    $module = 'dashboard';
}

~>include_once("modules/" . $module . "/index.php");
