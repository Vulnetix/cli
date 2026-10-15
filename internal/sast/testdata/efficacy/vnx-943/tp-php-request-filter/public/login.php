<?php
require __DIR__ . '/../vendor/autoload.php';

$client = new MongoDB\Client('mongodb://localhost:27017');
$users = $client->app->users;

~>$user = $users->findOne(['username' => $_POST['username'], 'password' => $_POST['password']]);

$name = $_GET['name'];
~>$cursor = $users->find(['name' => $name]);

~>$query = new MongoDB\Driver\Query(['owner' => $_REQUEST['owner']]);
