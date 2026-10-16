<?php

namespace App\Crypto;

final class Box
{
    public static function seal(string $plain, string $key): string
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        return base64_encode($nonce . $tag . $ct);
    }
}
