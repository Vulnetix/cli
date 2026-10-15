<?php
return [
    'mysql' => [
        'username' => env('DB_USERNAME', 'app'),
~>        'password' => env('DB_PASSWORD', 'secret'),
    ],
~>    'admin_password' => 'admin',
];
$dbPassword = getenv('DB_PASSWORD');
~>$password = "root";
