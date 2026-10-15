<?php
function migrate($text, array $vars)
{
    $hint = 'the old pattern /(\w+)/e was replaced by a callback';
    error_log($hint);
    return preg_replace_callback('/\{(\w+)\}/', function ($m) use ($vars) {
        return $vars[$m[1]] ?? '';
    }, $text);
}
