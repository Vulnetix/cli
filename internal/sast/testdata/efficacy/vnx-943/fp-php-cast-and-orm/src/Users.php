<?php

use App\Models\User;

class Users
{
    public function show($repo, $users)
    {
        $byId = $repo->find($_GET['id']);
        $row = $users->findOne(['username' => (string) $_POST['username']]);
        $other = $users->findOne(['email' => strval($_POST['email'])]);
        $fixed = $users->find(['$where' => 'this.active == true']);
        // $users->find(['name' => $_GET['name']]);
        return [$byId, $row, $other, $fixed];
    }
}
