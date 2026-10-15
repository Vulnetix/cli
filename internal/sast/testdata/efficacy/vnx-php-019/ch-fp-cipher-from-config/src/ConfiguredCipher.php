<?php
class ConfiguredCipher
{
    public function __construct(private array $config) {}

    public function encrypt($plain, $key, $iv)
    {
        $cipher = $this->config['cipher'];
        return openssl_encrypt($plain, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    }

    public function supported(): array
    {
        return ['aes-256-cbc' => 32, 'aes-128-cbc' => 16];
    }
}
