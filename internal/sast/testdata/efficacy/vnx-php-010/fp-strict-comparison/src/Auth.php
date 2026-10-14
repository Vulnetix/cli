<?php

class Auth
{
    public function check($name, $plain)
    {
        $stored = $this->repo->hashFor($name);
        if (password_verify($plain, $stored)) {
            return true;
        }
        if ($_POST['password'] === $stored) {
            return true;
        }
        if ($_GET['token'] !== $_SESSION['csrf_token']) {
            return false;
        }
        return hash_equals($stored, md5($plain));
    }

    public function sig($payload, $sig)
    {
        return hash_hmac('sha256', $payload, $this->key) === $sig;
    }
}

if (strcmp($_POST['password'], $adminPassword) === 0) {
    grant();
}
