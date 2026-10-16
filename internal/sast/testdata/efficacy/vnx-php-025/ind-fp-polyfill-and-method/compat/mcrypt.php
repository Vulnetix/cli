<?php
if (!function_exists('mcrypt_encrypt')) {
    function mcrypt_encrypt($cipher, $key, $data, $mode, $iv = null)
    {
        return openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }
}

class Facade
{
    public function mcrypt_encrypt($data)
    {
        return strrev($data);
    }

    public function run($data)
    {
        return $this->mcrypt_encrypt($data);
    }
}
