<?php

function render_bold($text)
{
~>    return preg_replace('/\[b\](.*?)\[\/b\]/e', '"<b>".strtoupper("$1")."</b>"', $text);
}

function render_tags($template, $vars)
{
~>    $out = preg_replace("/\{(\w+)\}/ei", '$vars["$1"]', $template);
    return $out;
}

function strip_filter($body)
{
~>    return preg_filter('/@@(\w+)@@/me', 'constant("$1")', $body);
}
