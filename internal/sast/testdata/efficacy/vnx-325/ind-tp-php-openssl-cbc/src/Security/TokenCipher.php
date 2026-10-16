<?php

namespace App\Security;

final class TokenCipher
{
    public function __construct(private string $key)
    {
    }

    public function encrypt(string $plain): string
    {
        $iv = random_bytes(16);
~>        $ct = openssl_encrypt($plain, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }
}
