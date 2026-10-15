<?php
function debug_echo()
{
    $key = $_GET['key'];
    echo htmlspecialchars($key, ENT_QUOTES);
}

function login_user(array $config, $user)
{
    $key = $config['session_key'];
    $_SESSION[$key] = $user->id;
    $name = session_name();
    $_SESSION[$name . '_ts'] = time();
}
