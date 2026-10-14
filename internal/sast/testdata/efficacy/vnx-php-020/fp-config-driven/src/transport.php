<?php
class Transport
{
    private $verifyTls = true;

    public function open($url)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifyTls);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verifyTls ? 2 : 0);
        return $ch;
    }
}
$rules = [
    'email' => 'required|email',
    'verify' => false,
];
