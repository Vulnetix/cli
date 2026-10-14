<?php

// The old parser used preg_replace('/\{(\w+)\}/e', '$vars["$1"]', $tpl);
/*
 * preg_replace('/x/e', 'y', $z) is removed in PHP 7.
 */
# preg_replace('#a#e', 'b', $c);

function describe()
{
    $msg = "Do not call preg_replace('/x/e', ...) any more";
    return $msg;
}
