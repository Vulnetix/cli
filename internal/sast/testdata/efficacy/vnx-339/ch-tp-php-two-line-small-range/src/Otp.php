<?php

function send_otp(string $phone): int
{
    $seed = rand(0, 9999);
~>    mt_srand($seed);
    $otp = mt_rand(100000, 999999);
    sms($phone, $otp);
    return $otp;
}
