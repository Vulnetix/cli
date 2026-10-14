<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function issue(array $user): string
{
~>    return JWT::encode(['sub' => $user['id']], 'php-jwt-secret', 'HS256');
}

function read(string $jwt): object
{
~>    return JWT::decode($jwt, new Key('php-jwt-secret', 'HS256'));
}
