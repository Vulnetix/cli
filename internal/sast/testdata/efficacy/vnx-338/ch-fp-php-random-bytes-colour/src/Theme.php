<?php

function theme_for(string $user): array
{
    $token = bin2hex(random_bytes(16));
    $color = rand(0, 255);
    $tokenCount = mt_rand(1, 5);
    return [$token, $color, $tokenCount];
}
