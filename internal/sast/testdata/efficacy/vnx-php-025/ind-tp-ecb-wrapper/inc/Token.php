<?php
final class Token
{
    public static function make($secret, $payload)
    {
~>        $out = mcrypt_ecb(MCRYPT_DES, $secret, $payload, MCRYPT_ENCRYPT);
        return bin2hex($out);
    }
}
