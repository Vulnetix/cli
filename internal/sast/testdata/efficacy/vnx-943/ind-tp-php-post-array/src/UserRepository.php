<?php

namespace App;

use MongoDB\Client;

class LoginController
{
    public function handle(): void
    {
        $client = new Client('mongodb://127.0.0.1:27017');
        $users = $client->app->users;
~>        $user = $users->findOne(['username' => $_POST['username'], 'password' => $_POST['password']]);
        if ($user === null) {
            http_response_code(401);
            return;
        }
        $_SESSION['uid'] = (string) $user['_id'];
    }
}
