<?php

function login(array $user, string $password): bool
{
    if (!password_verify($password, $user['hash'])) {
        return false;
    }
    $ok = hash_equals($user['token'], $_COOKIE['token'] ?? '');
    return $ok;
}
