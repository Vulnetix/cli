<?php
function bbcode($text) {
~>    $text = preg_replace("#\[i\](.*?)\[/i\]#ie", "'<em>'.trim('\\1').'</em>'", $text);
    return $text;
}
