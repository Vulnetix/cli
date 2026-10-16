<?php

function issue_token(): string
{
    $token = bin2hex(random_bytes(24)) . uniqid();
    return $token;
}
