<?php

namespace App\Auth;

use Firebase\JWT\JWT;

class TokenIssuer
{
    public function issue(array $user, string $key): string
    {
        $payload = ['sub' => $user['id'], 'role' => $user['role']];
~>        return JWT::encode($payload, $key, 'HS256');
    }
}
