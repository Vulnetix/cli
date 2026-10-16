<?php
namespace App\Webhook;

final class Verifier
{
    public function verify(string $data, string $sig, $pub): void
    {
        if (openssl_verify($data, $sig, $pub, OPENSSL_ALGO_SHA256) !== 1) {
            throw new InvalidSignature();
        }
    }

    public function login(string $password, string $hash): bool
    {
        $ok = password_verify($password, $hash);
        return $ok && hash_equals($hash, $hash);
    }
}
