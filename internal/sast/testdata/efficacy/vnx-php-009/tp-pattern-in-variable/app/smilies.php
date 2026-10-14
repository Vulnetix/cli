<?php

function apply_smilies($text, $table)
{
    $pattern = '/:(\w+):/e';
    $replacement = 'smiley_html("$1", $table)';
~>    return preg_replace($pattern, $replacement, $text);
}

function apply_macros($text)
{
    $patterns = array(
        '/\$\{date\}/',
        '/\$\{(\w+)\}/e',
    );
~>    return preg_replace($patterns, array(date('Y'), 'getenv("$1")'), $text);
}
