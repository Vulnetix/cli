<?php

function issue_reset_token(): string
{
~>    $resetToken = bin2hex(random_bytes(8));
    return $resetToken;
}

function api_key(): string
{
~>    $apiKey = 'ak_' . bin2hex(openssl_random_pseudo_bytes(6));
    return $apiKey;
}

function session_id_for($user)
{
~>    $_SESSION['session_id'] = base64_encode(random_bytes(10));
}
