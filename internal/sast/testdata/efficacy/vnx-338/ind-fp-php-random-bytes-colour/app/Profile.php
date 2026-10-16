<?php

class Profile
{
    public function newToken(): string
    {
        $token = bin2hex(random_bytes(32));
        $pin = random_int(100000, 999999);
        return $token . ':' . $pin;
    }

    public function avatarColour(): string
    {
        $colour = sprintf('#%06X', mt_rand(0, 0xFFFFFF));
        return $colour;
    }
}
