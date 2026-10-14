<?php
header('X-Frame-Options: SAMEORIGIN');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
// header('X-Frame-Options: ALLOWALL');
$response->headers->set('X-Frame-Options', 'DENY', false);
echo "Framing is blocked by X-Frame-Options: DENY";
