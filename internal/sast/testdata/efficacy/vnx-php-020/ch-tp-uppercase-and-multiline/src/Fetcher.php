<?php
class Fetcher
{
    public function get($url)
    {
        $ch = curl_init($url);
~>        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
~>        curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,0);
        curl_setopt(
            $ch,
~>            CURLOPT_SSL_VERIFYPEER,
            false
        );
        return curl_exec($ch);
    }
}
