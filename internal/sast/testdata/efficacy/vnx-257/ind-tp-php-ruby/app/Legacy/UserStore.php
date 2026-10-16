<?php

class UserStore
{
    private PDO $db;
    private string $key;

    public function save(string $email): void
    {
~>        $stored = base64_encode($_POST['password']);
        $this->db->prepare('INSERT INTO users (email, pw) VALUES (?, ?)')->execute([$email, $stored]);
    }

    public function saveEncrypted(string $email, string $password): void
    {
        $iv = random_bytes(16);
~>        $enc = openssl_encrypt($password, 'aes-256-cbc', $this->key, 0, $iv);
        $this->db->prepare('INSERT INTO users (email, pw, iv) VALUES (?, ?, ?)')->execute([$email, $enc, $iv]);
    }
}
