<?php
function login($user, $password) {
~>    password_verify($password, $user->hash);
    $_SESSION['uid'] = $user->id;
}

function checkLicense($data, $sig, $pub) {
~>    if (openssl_verify($data, $sig, $pub, OPENSSL_ALGO_SHA256)) {
        return true;
    }
~>    hash_equals($sig, hash_hmac('sha256', $data, KEY));
    return false;
}
