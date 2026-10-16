<?php

function bbcode_to_html($text)
{
    $text = htmlspecialchars($text, ENT_QUOTES);
~>    $text = preg_replace('#\[url=(.*?)\](.*?)\[/url\]#ise', "'<a href=\"'.urlencode('\\1').'\">\\2</a>'", $text);
    $text = preg_replace('#\[i\](.*?)\[/i\]#is', '<em>$1</em>', $text);
    return nl2br($text);
}
