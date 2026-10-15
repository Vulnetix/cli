<?php

namespace App\Auth;

class Tokens
{
    public function issue(): string
    {
~>        $token = md5(mt_rand());
~>        $_SESSION['csrf_token'] = substr(str_shuffle('@@sample:a[b]cd[e]f0[1]23[4]56[7]89[a]bc[d]ef[0]12[3]45[6]78[9]@@'), 0, 32);
        return $token;
    }

    public function generatePassword(int $len = 12): string
    {
~>        return substr(str_shuffle(str_repeat('@@sample:a[b]cd[e]fg[h]jk[m]np[q]rs[t]uv[w]xy[z]23[4]56[7]89@@', 3)), 0, $len);
    }

    public function sendOtp($user): void
    {
~>        $otp = rand(100000, 999999);
        $user->notify($otp);
    }
}
