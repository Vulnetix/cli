<?php

class Crypto
{
    const KEY = 'k';

    public static function encrypt(string $plain): string
    {
~>        return openssl_encrypt($plain, 'aes-256-cbc', self::KEY, 0, '1234567890123456');
    }

    public static function decrypt(string $blob): string
    {
~>        $iv = str_repeat("\0", 16);
        return openssl_decrypt($blob, 'aes-256-cbc', self::KEY, 0, $iv);
    }

    public static function hashPassword(string $pw): string
    {
~>        return hash_pbkdf2('sha256', $pw, 'site-wide-salt', 100000, 64);
    }
}
