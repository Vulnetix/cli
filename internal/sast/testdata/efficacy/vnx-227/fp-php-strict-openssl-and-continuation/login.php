<?php
function login($user, $password) {
    if (!password_verify($password, $user->hash)) {
        throw new AuthException();
    }
    if (openssl_verify($data, $sig, $pub, OPENSSL_ALGO_SHA256) === 1) {
        return true;
    }
    return is_string($token) &&
        hash_equals($expected, $token);
}
