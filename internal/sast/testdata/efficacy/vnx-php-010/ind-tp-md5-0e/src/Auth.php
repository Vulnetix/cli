<?php

function checkToken($user, $token) {
~>    if (md5($token . $user['salt']) == $user['token_hash']) {
        return true;
    }
    return false;
}
