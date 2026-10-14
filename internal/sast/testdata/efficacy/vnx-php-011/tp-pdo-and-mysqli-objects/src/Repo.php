<?php

class Repo
{
    public function find(PDO $pdo)
    {
        $name = $_POST['name'];
~>        $stmt = $pdo->query("SELECT * FROM users WHERE name = '$name'");
        return $stmt->fetchAll();
    }

    public function purge($db)
    {
~>        $db->exec('DELETE FROM sessions WHERE user = ' . $_GET['user']);
    }

    public function prepareWrong(mysqli $m)
    {
        $email = $_POST['email'];
~>        $st = $m->prepare("SELECT id FROM users WHERE email = '" . $email . "'");
        $st->execute();
    }
}
