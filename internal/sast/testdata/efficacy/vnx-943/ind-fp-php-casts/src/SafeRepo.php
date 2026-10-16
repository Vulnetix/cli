<?php

namespace App;

class SafeRepo
{
    public function login($users): bool
    {
        $name = (string) $_POST['username'];
        $pass = strval($_POST['password']);
        $user = $users->findOne(['username' => $name, 'password' => $pass]);
        return $user !== null;
    }

    public function byId($items)
    {
        return $items->findOne(['_id' => new \MongoDB\BSON\ObjectId((string) $_GET['id'])]);
    }

    public function lowStock($items)
    {
        return $items->find(['$where' => 'this.stock < this.reorderLevel']);
    }

    public function note(): string
    {
        // $users->findOne(['username' => $_POST['username']]) would be unsafe
        return "ok";
    }
}
