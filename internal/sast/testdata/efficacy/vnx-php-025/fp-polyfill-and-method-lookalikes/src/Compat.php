<?php

class LegacyBridge
{
    public function mcrypt_encrypt($cipher, $key, $data)
    {
        return openssl_encrypt($data, 'aes-256-gcm', $key, 0, random_bytes(12), $tag);
    }

    public static function mcrypt_decrypt($cipher, $key, $data)
    {
        return '';
    }

    public function run($key, $data)
    {
        $a = $this->mcrypt_encrypt('aes', $key, $data);
        $b = self::mcrypt_decrypt('aes', $key, $a);
        $c = my_mcrypt_encrypt($key, $data);
        $d = $obj->mcrypt_generic($data);
        return [$a, $b, $c, $d];
    }
}

if (!function_exists('mcrypt_encrypt')) {
    function mcrypt_encrypt($cipher, $key, $data, $mode, $iv = null)
    {
        return openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }
}
