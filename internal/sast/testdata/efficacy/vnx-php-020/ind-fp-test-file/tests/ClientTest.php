<?php
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    public function testSelfSigned()
    {
        $c = new \GuzzleHttp\Client(['verify' => false]);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $this->assertNotNull($c);
    }
}
