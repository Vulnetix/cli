<?php
function make_hash($password, $salt)
{
~>    $a = hash('md5', $password . $salt);
~>    $b = crypt($password, '$1$' . $salt . '$');
~>    $c = md5(md5($password));
    return [$a, $b, $c];
}
