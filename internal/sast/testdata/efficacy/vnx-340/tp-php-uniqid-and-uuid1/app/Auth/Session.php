<?php

use Ramsey\Uuid\Uuid;

function checkToken()
{
~>    $_SESSION['session_token'] = md5(uniqid());
~>    $token = uniqid('', true);
~>    $resetToken = Uuid::uuid1()->toString();
    return [$token, $resetToken];
}
