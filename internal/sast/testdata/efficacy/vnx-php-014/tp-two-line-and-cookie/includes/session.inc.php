<?php

function resume_session()
{
    if (isset($_COOKIE[session_name()])) {
~>        session_id($_COOKIE[session_name()]); // keep the same id
    }
    $sid = $_POST['session'];
    if ($sid) {
~>        session_id($sid);
    }
    session_start();
}
