<?php
require 'vendor/autoload.php';

$client = new MongoDB\Client('mongodb://localhost:27017');
$users = $client->app->users;

~>$user = $users->findOne([
    'username' => $_POST['username'],
    'password' => $_POST['password'],
]);

if ($user) {
    $_SESSION['uid'] = (string) $user['_id'];
}
