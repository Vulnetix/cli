<?php

use Firebase\JWT\JWT;

function issue(array $payload): string
{
    return JWT::encode($payload, getenv('JWT_SECRET'), 'HS256');
}
