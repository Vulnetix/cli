<?php

function oauth_signature($base, $key) {
    return base64_encode(hash_hmac('sha1', $base, $key, true));
}

function derive($password, $salt) {
    return hash_pbkdf2('sha1', $password, $salt, 310000);
}
