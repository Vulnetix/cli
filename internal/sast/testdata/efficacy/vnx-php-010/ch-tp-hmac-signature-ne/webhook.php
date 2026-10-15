<?php
$payload = file_get_contents('php://input');
$key = getenv('WEBHOOK_SECRET');
~>if (hash_hmac('sha256', $payload, $key) != $_SERVER['HTTP_X_SIGNATURE']) {
    http_response_code(401);
    exit;
}
