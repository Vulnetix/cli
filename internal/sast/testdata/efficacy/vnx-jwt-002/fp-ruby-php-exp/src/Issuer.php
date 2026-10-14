<?php

use Firebase\JWT\JWT;

function issue(array $user, string $key): string
{
    $payload = ['sub' => $user['id'], 'exp' => time() + 900];
    return JWT::encode($payload, $key, 'HS256');
}
