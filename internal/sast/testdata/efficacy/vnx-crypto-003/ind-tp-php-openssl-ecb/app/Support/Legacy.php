<?php

namespace App\Support;

class Legacy
{
    public static function decode(string $blob, string $key): string|false
    {
~>        return openssl_decrypt(base64_decode($blob), 'AES-256-ECB', $key, OPENSSL_RAW_DATA);
    }
}
