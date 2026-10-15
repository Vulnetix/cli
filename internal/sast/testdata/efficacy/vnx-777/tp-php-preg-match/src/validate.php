<?php

function valid_user_id($id)
{
~>    if (!preg_match('/^[0-9]+/', $id)) {
        return false;
    }
    return true;
}

function valid_color($c)
{
~>    return preg_match("/[a-f0-9]{6}$/i", $c) === 1;
}
