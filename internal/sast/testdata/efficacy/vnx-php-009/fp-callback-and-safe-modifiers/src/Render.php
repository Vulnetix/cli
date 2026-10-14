<?php

function render_bold($text)
{
    return preg_replace_callback('/\[b\](.*?)\[\/b\]/', function ($m) {
        return '<b>' . htmlspecialchars($m[1], ENT_QUOTES, 'UTF-8') . '</b>';
    }, $text);
}

function squash($text)
{
    $text = preg_replace('/\s+/ims', ' ', $text);
    $text = preg_replace('#<br\s*/?>#i', "\n", $text);
    $text = preg_replace('/^[ ]{0,4}+/', '', $text);
    $text = preg_replace("/[^a-z0-9]+/u", '-', strtolower($text));
    return preg_replace('{\s+}', ' ', $text);
}

function edit_path($path)
{
    $pattern = '/edit/';
    return preg_replace($pattern, 'view', $path);
}
