<?php
namespace App\Security;

class LegacyCrypt
{
    public function seal(string $key, string $data): string
    {
        $iv = random_bytes(8);
~>        $ct = mcrypt_encrypt(MCRYPT_BLOWFISH, $key, $data, MCRYPT_MODE_CBC, $iv);
        return base64_encode($iv . $ct);
    }

    public function open(string $key, string $blob): string
    {
        $raw = base64_decode($blob);
        $iv = substr($raw, 0, 8);
~>        return mcrypt_decrypt(
            MCRYPT_BLOWFISH,
            $key,
            substr($raw, 8),
            MCRYPT_MODE_CBC,
            $iv
        );
    }
}
