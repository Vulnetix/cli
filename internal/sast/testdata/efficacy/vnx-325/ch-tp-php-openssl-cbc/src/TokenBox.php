<?php

namespace App\Security;

class TokenBox
{
~>    private const CIPHER = 'aes-256-cbc';

    public function seal(string $plain, string $key): string
    {
        $iv = random_bytes(16);
        $ct = openssl_encrypt($plain, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }

    public function open(string $blob, string $key): string
    {
        $raw = base64_decode($blob);
~>        return openssl_decrypt(substr($raw, 16), "AES-128-CTR", $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    }
}
