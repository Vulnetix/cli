<?php

class Remember
{
    public function issue($user)
    {
~>        mt_srand(time());
        $token = md5(mt_rand());
~>        srand((int) (microtime(true) * 1000000));
        $user->remember_token = $token;
    }
}
