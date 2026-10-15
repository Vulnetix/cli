<?php
function login($user)
{
    session_regenerate_id(true);
    $newId = session_create_id('app-');
    session_id($newId);
    session_id(bin2hex(random_bytes(16)));
}
