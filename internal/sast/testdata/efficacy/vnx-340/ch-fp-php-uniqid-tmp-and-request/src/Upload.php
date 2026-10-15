<?php

function stage_upload(array $file): string
{
    $tmp = '/tmp/upload_' . uniqid();
    $requestId = uniqid('req_');
    $token = bin2hex(random_bytes(16)) . uniqid();
    move_uploaded_file($file['tmp_name'], $tmp);
    return $requestId;
}
