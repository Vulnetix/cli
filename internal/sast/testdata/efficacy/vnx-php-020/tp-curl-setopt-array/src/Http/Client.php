<?php
namespace App\Http;

class Client
{
    public function post($url, array $fields)
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields),
~>            CURLOPT_SSL_VERIFYPEER => false,
~>            CURLOPT_SSL_VERIFYHOST => 0,
        ]);
        return curl_exec($ch);
    }
}
