<?php

function cache_path($key)
{
    $parts = array_slice(str_split($hash = sha1($key), 2), 0, 2);
    return implode('/', $parts);
}

function verify_email($user, $route)
{
    return hash_equals(sha1($user->getEmailForVerification()), (string) $route->hash);
}

function pwned_prefix($value)
{
    $hash = strtoupper(sha1((string) $value));
    return substr($hash, 0, 5);
}

$sessionToken = md5(uniqid());
