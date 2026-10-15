<?php
var_dump(count($_SESSION));
print_r(array_keys($_SESSION['cart'] ?? []));
var_dump($_SERVER['REQUEST_METHOD']);
echo getenv('APP_ENV');
$_SESSIONS = [];
print_r($_SESSIONS);
