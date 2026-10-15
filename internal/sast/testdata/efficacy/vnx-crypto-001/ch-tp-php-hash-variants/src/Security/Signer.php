<?php
namespace App\Security;

class Signer
{
    public function sign(string $payload): string
    {
~>        return hash('md5', $payload . $this->secret);
    }

    public function fileSig(string $path): string
    {
~>        return md5_file($path);
    }

    public function stream(): string
    {
~>        $ctx = hash_init("MD5");
        hash_update($ctx, $this->secret);
        return hash_final($ctx);
    }
}
