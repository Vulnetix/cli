<?php

function handle_webhook(array $headers, string $body): void
{
    $expected = hash_hmac('sha256', $body, getenv('WEBHOOK_SECRET'));
~>    # if (!hash_equals($expected, $headers['X-Signature'] ?? '')) {
    #     http_response_code(403);
    #     exit;
    # }
    process_event(json_decode($body, true));
}
