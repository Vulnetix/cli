<?php
function bbcode_to_html($text)
{
~>    $text = \preg_replace(
        '{\[b\](.*?)\[/b\]}ie',
        "strtoupper('<b>\\1</b>')",
        $text
    );
    return $text;
}
