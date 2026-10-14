<?php

$data = json_decode(file_get_contents('php://input'));
$secret = getenv('HOOK_SECRET');

~>if ($data->secret == $secret) {
    process($data);
}
