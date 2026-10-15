<?php

use Firebase\JWT\JWT;

function issue(array $user, string $key): string
{
    $payload = [
        'sub' => $user['id'],
~>        'card_number' => $user['card_number'],
        'exp' => time() + 3600,
    ];
    return JWT::encode($payload, $key, 'HS256');
}
