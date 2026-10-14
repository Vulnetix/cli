<?php
class ApiTest extends TestCase
{
    public function testLocalServer()
    {
        $ch = curl_init('https://localhost:8443/');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $client = new \GuzzleHttp\Client(['verify' => false]);
    }
}
