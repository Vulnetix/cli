<?php
$allowed = ['UTC', 'Europe/Berlin', 'America/New_York'];

$tz = $_POST['tz'] ?? 'UTC';
if (!in_array($tz, $allowed, true)) {
    http_response_code(400);
    exit;
}
putenv("TZ=" . $tz);

ini_set('memory_limit', '256M');
echo date('c');
