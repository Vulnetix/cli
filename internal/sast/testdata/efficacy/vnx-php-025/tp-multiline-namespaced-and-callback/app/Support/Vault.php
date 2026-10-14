<?php

namespace App\Support;

final class Vault
{
    public static function lock(string $key, string $data): string
    {
        $iv = random_bytes(16);
~>        $enc = \mcrypt_encrypt(
            MCRYPT_RIJNDAEL_256,
            $key,
            $data,
            MCRYPT_MODE_CBC,
            $iv
        );
        return $iv . $enc;
    }

    public static function unlock(string $key, string $data, string $iv): string
    {
~>        return call_user_func('mcrypt_decrypt', MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_CBC, $iv);
    }

    public static function viaArray(array $args): string
    {
~>        return call_user_func_array("mcrypt_encrypt", $args);
    }
}
