<?php
function check_login($user, $pwd)
{
~>    $stored = sha1($pwd);
    return $stored === $user['pw'];
}
~>$user->password = sha1($salt . $pass);
