<?php

function limiter_key($name, $key) {
    return md5($name . $key);
}

function reset_digest($user) {
    return hash('sha256', $user->getEmailForPasswordReset());
}
