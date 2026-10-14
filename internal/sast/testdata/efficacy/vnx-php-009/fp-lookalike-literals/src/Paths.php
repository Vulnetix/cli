<?php

function normalise($subject)
{
    $subject = preg_replace('/\/home\/(\w+)\/file/', '/srv/$1', $subject);
    $subject = preg_replace('/node/', 'edge', $subject);
    return preg_match('/abc/e', $subject);
}

function my_preg_replace($a, $b, $c)
{
    return str_replace($a, $b, $c);
}

$out = my_preg_replace('/x/e', 'y', 'z');
