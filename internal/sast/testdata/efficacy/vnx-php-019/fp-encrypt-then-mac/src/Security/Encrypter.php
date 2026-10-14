<?php
namespace App\Security;

class Encrypter
{
    private $key;
    private $cipher = 'aes-256-cbc';

    public function encrypt($value)
    {
        $iv = random_bytes(16);
        $method = 'aes-256-cbc';
        $ct = openssl_encrypt($value, $method, $this->key, 0, $iv);
        $mac = hash_hmac('sha256', base64_encode($iv) . $ct, $this->key);
        return base64_encode(json_encode(['iv' => base64_encode($iv), 'value' => $ct, 'mac' => $mac]));
    }
}
