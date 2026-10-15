<?php

namespace App\Support;

class CookieCipher
{
    private const CIPHER = 'aes-256-cbc';
    protected $method = 'CAMELLIA-256-CBC';

    public function decode(string $payload, string $key, string $iv)
    {
~>        return openssl_decrypt($payload, self::CIPHER, $key, 0, $iv);
    }

    public function encode(string $value, string $key, string $iv)
    {
~>        return openssl_encrypt($value, $this->method, $key, 0, $iv);
    }
}
