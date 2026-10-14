<?php

function format_message($message)
{
~>    $message = preg_replace(
        '/\[url=(.*?)\](.*?)\[\/url\]/e',
        "make_link('\\1', '\\2')",
        $message
    );

~>    return preg_replace(array('/\[i\](.*?)\[\/i\]/e', '/\[u\](.*?)\[\/u\]/e'), array('italic("$1")', 'underline("$1")'), $message);
}
