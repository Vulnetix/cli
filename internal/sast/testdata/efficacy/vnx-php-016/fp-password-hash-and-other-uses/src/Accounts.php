<?php

class Accounts
{
    public function register($name, $password)
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $ok = password_verify($password, $hash);
        $etag = md5($body);
        $cacheKey = sha1($name . $locale);
        $token = hash('sha256', random_bytes(32));
        $h = hash('sha256', $password . $pepper);
        $checksum = md5_file($path);
        $bypass = md5($bypassRoute);
        return [$hash, $ok, $etag, $cacheKey, $token, $h, $checksum, $bypass];
    }
}
