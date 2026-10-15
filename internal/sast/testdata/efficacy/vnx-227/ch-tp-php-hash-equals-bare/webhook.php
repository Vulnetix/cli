<?php

function handle_webhook(string $body, string $signature, string $secret): void
{
    $expected = hash_hmac('sha256', $body, $secret);
~>    hash_equals($expected, $signature);
    process_event(json_decode($body, true));
}
