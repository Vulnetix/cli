<?php

namespace App\Auth;

use Firebase\JWT\JWT;

class TokenIssuer
{
    public function issue(array $payload): string
    {
~>        return JWT::encode($payload, '@@sample:k[3]y[-][f]or[-]si[g]ni[n]g[-][t]ok[e]ns@@', 'HS256');
    }
}
