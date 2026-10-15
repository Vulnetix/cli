<?php
namespace App\Session;

function resume()
{
    $sid = $_COOKIE['sid'] ?? '';
    if ($sid !== '') {
~>        session_id($sid);
    }
    session_start();
}
