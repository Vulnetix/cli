<?php
function verify_sig($payload, $key, $sig)
{
    if (!hash_equals(hash_hmac('sha256', $payload, $key), $sig)) {
        return false;
    }
    return md5($payload) === $sig;
}
