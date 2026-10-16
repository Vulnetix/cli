<?php

function client_ip(): string
{
~>    $ip = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'];
    return trim(explode(',', $ip)[0]);
}
