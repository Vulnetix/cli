<?php
function fetch_feed($url)
{
~>    $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'allow_self_signed' => true]]);
    return file_get_contents($url, false, $ctx);
}
