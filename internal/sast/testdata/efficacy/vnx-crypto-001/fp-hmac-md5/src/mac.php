<?php

function sign_request($key, $body) {
    return hash_hmac('md5', $body, $key);
}
