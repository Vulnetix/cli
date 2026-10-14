<?php

class Accounts
{
    public function register($name, $password)
    {
~>        $digest = sha1($this->salt . $password);
~>        $h = hash('md5', $password);
~>        $h2 = hash("sha1", $userPassword . $salt);
~>        if (md5($plainPassword) === $row['pw']) {
            return true;
        }
        return $digest . $h . $h2;
    }
}
