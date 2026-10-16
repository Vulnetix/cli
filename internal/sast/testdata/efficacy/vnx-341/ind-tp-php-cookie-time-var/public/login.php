<?php

if ($user = authenticate($_POST['username'], $_POST['password'])) {
~>    $sessionValue = time();
    setcookie('app_session', $sessionValue, ['httponly' => true, 'samesite' => 'Lax']);
    store_session($sessionValue, $user['id']);
}
