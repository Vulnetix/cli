<?php

$row = fetch_user($_POST['username']);

~>if ($_POST['password'] == $row['password']) {
    login($row);
}

$token = $_GET['token'];
~>if ($token != $_SESSION['csrf_token']) {
    die('bad token');
}

~>if ($_COOKIE['remember'] == $user->rememberToken) {
    resume($user);
}

~>if (get_api_key($tenant) == $_SERVER['HTTP_X_API_KEY']) {
    allow();
}
