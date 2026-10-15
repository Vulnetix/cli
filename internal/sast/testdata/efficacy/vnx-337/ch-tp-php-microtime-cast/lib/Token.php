<?php

class TokenFactory
{
    public function create(): string
    {
~>        mt_srand((int) (microtime(true) * 1000000));
        $token = sha1((string) mt_rand());
        return $token;
    }
}
