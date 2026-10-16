<?php

function bbcode_to_html($text)
{
    $text = htmlspecialchars($text, ENT_QUOTES);
    $text = preg_replace_callback(
        '#\[b\](.*?)\[/b\]#is',
        fn ($m) => '<strong>' . $m[1] . '</strong>',
        $text
    );
    return $text;
}
