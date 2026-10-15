<?php
class Envelope
{
    public function seal($plain, $encKey, $macKey, $iv)
    {
        $ct = openssl_encrypt($plain, 'aes-256-cbc', $encKey, OPENSSL_RAW_DATA, $iv);
        $mac = sodium_crypto_auth($iv . $ct, $macKey);
        return $mac . $iv . $ct;
    }
}
