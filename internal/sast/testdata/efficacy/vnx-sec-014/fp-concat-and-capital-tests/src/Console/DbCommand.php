<?php
function args(array $connection): array {
    return [
        'password' => '--password='.$connection['password'],
        'user' => '--user='.$connection['username'],
    ];
}
