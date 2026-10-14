<?php

class Session
{
    public function start()
    {
        session_id(bin2hex(random_bytes(32)));
        session_start();
        $current = session_id();
        if (session_id() === '') {
            session_start();
        }
        $sid = session_create_id('app-');
        session_id($sid);
        return $current;
    }
}
