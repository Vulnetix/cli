<?php

class Vault
{
    public function seal(string $data, $publicKey): string
    {
~>        openssl_public_encrypt($data, $sealed, $publicKey);
        return base64_encode($sealed);
    }

    public function open(string $blob, $privateKey): string
    {
~>        openssl_private_decrypt(base64_decode($blob), $plain, $privateKey, @@sample:O[P]EN[S]SL[_]PK[C]S1[_]PA[D]DI[N]G@@);
        return $plain;
    }

    public function legacy($rsa)
    {
~>        $rsa->setEncryptionMode(@@sample:C[R]YP[T][_]R[S]A[_][E]NC[R]YP[T]IO[N][_]P[K]CS[1]@@);
~>        return $rsa->withPadding(RSA::ENCRYPTION_PKCS1);
    }
}
