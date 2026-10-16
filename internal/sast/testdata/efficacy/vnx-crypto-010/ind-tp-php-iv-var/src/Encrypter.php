<?php

namespace App\Support;

class Encrypter
{
    private string $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    public function encrypt(string $plain): string
    {
~>        $iv = '0102030405060708';
        $ct = openssl_encrypt($plain, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($ct);
    }

    public function hashPassword(string $pw): string
    {
~>        return hash_pbkdf2('sha256', $pw, 'global-salt-2020', 100000, 64);
    }
}
