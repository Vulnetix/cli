<?php

class NotPwned
{
    public function verify($password)
    {
        $hash = strtoupper(sha1((string) $password));
        $prefix = substr($hash, 0, 5);
        return $this->http->get('https://api.pwnedpasswords.com/range/'.$prefix);
    }
}
