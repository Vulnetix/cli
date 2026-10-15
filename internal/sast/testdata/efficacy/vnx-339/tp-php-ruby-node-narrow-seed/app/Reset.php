<?php

class Reset
{
    public function send($email)
    {
~>        mt_srand(strlen($email));
        $resetCode = mt_rand(100000, 999999);
~>        mt_srand(rand(0, 999));
        $csrfToken = dechex(mt_rand());
        return [$resetCode, $csrfToken];
    }
}
