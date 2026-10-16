<?php

class Repo {
    public function find(PDO $pdo) {
        $name = $_POST['name'];
~>        $stmt = $pdo->query("SELECT id FROM accounts WHERE name = '$name'");
        return $stmt->fetchAll();
    }
}
