<?php
function bbcode($text)
{
~>    $text = preg_replace(array('/\[b\](.*?)\[\/b\]/is', '/\[url=(.*?)\](.*?)\[\/url\]/ie'), array('<b>$1</b>', 'make_link("$1", "$2")'), $text);
    return preg_replace(
~>        "#\[color=(\w+)\](.*?)\[/color\]#sie",
        "colourise('\\1', '\\2')",
        $text
    );
}
