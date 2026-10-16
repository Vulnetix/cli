<?php
require __DIR__ . '/../bootstrap.php';

session_start();

if (!empty($_GET['errors'])) {
~>    ini_set('display_errors', $_GET['errors']);
}

$tz = $_POST['tz'] ?? 'UTC';
~>putenv("TZ=" . $tz);

echo render('debug', ['time' => date('c')]);
