<?php

class TokenCipher
{
    private $key;

    public function __construct($key)
    {
        $this->key = $key;
    }

    public function seal($plain)
    {
        $iv = random_bytes(16);
~>        $out = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->key, $plain, MCRYPT_MODE_CBC, $iv);
        return base64_encode($iv . $out);
    }

    public function open($blob)
    {
        $raw = base64_decode($blob);
        $iv = substr($raw, 0, 16);
~>        return rtrim(mcrypt_decrypt( MCRYPT_RIJNDAEL_128, $this->key, substr($raw, 16), MCRYPT_MODE_CBC, $iv ), "\0");
    }
}
