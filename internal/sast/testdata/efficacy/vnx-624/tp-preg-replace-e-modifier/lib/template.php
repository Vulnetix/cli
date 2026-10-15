<?php
function render($tpl, $vars) {
~>    return preg_replace('/\{\$(\w+)\}/e', '$vars["\\1"]', $tpl);
}

function bbcode($text) {
~>    $text = preg_replace("#\[b\](.*?)\[/b\]#ie", "'<b>'.strtoupper('\\1').'</b>'", $text);
~>    $text = preg_replace( '~\[url=(.+?)\]~sie' , 'make_link("\\1")', $text );
    return $text;
}
