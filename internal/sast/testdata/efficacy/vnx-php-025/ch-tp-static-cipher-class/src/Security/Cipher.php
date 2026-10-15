<?php
namespace App\Security;

final class Cipher
{
    public static function encrypt(string $key, string $plain): string
    {
        $ivSize = \mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CFB);
~>        $iv = \mcrypt_create_iv($ivSize, MCRYPT_RAND);
~>        return $iv . \mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $plain, MCRYPT_MODE_CFB, $iv);
    }

    public static function decryptAll(string $key, array $items): array
    {
~>        return array_map(fn ($c) => \call_user_func('mcrypt_decrypt', MCRYPT_RIJNDAEL_256, $key, $c, MCRYPT_MODE_CFB), $items);
    }
}
