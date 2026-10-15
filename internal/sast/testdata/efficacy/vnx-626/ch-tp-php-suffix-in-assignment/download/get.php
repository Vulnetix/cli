<?php
$file = 'reports/' . $_GET['report'] . '.pdf';
header('Content-Type: application/pdf');
~>readfile($file);

$cfg = "conf/{$_COOKIE['profile']}.ini";
~>$settings = parse_ini_file($cfg);
