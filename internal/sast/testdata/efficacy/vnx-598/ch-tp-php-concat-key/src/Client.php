<?php

class Client
{
    public function lookup($apiKey, $ip)
    {
~>        $body = file_get_contents("https://geo.example.com/json?ip=" . $ip . "&key=" . $apiKey);
        return json_decode($body, true);
    }
}
