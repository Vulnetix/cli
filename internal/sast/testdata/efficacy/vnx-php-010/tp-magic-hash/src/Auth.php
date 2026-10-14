<?php

class Auth
{
    public function check($name, $plain)
    {
        $stored = $this->repo->hashFor($name);
~>        if (md5($plain) == $stored) {
            return true;
        }
~>        return $stored == sha1($plain . $this->salt);
    }

    public function verifySignature($payload, $sig)
    {
~>        return hash_hmac('sha256', $payload, $this->key) == $sig;
    }
}

$token = $_POST['token'];
~>if ($token == md5(str_rot13("success"))) {
    echo "ok";
}
