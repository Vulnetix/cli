<?php
require __DIR__ . '/../bootstrap.php';

~>header('X-Frame-Options: ALLOWALL');
~>header("Content-Security-Policy: default-src 'self'; frame-ancestors *");

if (isset($_GET['legacy'])) {
~>    header_remove('X-Frame-Options');
}

echo render('embed', ['user' => current_user()]);
