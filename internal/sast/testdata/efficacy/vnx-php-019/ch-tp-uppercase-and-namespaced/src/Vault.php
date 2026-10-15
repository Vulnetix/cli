<?php
namespace Acme\Crypto;

final class Vault
{
    public function seal(string $data, string $key, string $iv): string
    {
~>        return \openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    public function open(string $ct, string $key, string $iv): string
    {
~>        return openssl_decrypt($ct, "aes128", $key, OPENSSL_RAW_DATA, $iv);
    }
}
