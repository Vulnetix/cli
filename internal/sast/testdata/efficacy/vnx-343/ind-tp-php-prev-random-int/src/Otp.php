<?php

function next_otp(int $prev_otp): int
{
~>    $otp = $prev_otp + random_int(1, 50);
    return $otp % 1000000;
}
