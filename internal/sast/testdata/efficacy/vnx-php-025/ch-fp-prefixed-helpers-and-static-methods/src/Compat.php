<?php
namespace App;

use phpseclib3\Crypt\AES;

final class Compat
{
    public static function mcrypt_encrypt($cipher, $key, $data, $mode)
    {
        $aes = new AES('cbc');
        $aes->setKey($key);
        return $aes->encrypt($data);
    }
}

function legacy_mcrypt_encrypt($key, $data)
{
    return Compat::mcrypt_encrypt('rijndael-128', $key, $data, 'cbc');
}

function my_mcrypt_decrypt($key, $data)
{
    return openssl_decrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA);
}

$sealed = legacy_mcrypt_encrypt($k, $msg);
$again = $compat->mcrypt_decrypt($k, $sealed);
$also = $compat?->mcrypt_generic($sealed);
