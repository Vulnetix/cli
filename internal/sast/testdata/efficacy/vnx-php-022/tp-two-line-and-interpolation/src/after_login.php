<?php
function finish_login()
{
    $next = $_POST['next'];
~>    header("Location: $next", true, 302);
    exit;
}

function back_to()
{
    $target = trim($_REQUEST['return_to']);
    $url = $target;
~>    header( "Location: {$url}" );
    exit;
}
