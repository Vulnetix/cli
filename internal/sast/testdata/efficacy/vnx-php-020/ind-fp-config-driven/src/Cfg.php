<?php
class Http
{
    public function __construct(private bool $verifyTls) {}
    public function apply($ch)
    {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifyTls);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verifyTls ? 2 : 0);
    }
}
