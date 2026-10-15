<?php

function pick(array $items)
{
    $index = random_int(0, count($items) - 1);
    $delay = mt_rand(100, 500);
    $token = bin2hex(random_bytes(32));
    $otp = random_int(100000, 999999);
    return [$items[$index], $delay, $token, $otp];
}
