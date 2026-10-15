<?php

function issue_csrf_token(): string
{
~>    mt_srand(0xC0FFEE);
    $csrf_token = dechex(mt_rand()) . dechex(mt_rand());
    $_SESSION['csrf_token'] = $csrf_token;
    return $csrf_token;
}
