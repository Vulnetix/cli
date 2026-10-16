<?php

// Old code used preg_replace('/x/e', 'strtoupper("\\1")', $s); which was removed in PHP 7.
/* preg_replace('/a/e', 'b', $x) */
$msg = "Do not call preg_replace('/a/e', 'b', $x) any more";
echo preg_match('/foo/e', $msg) ? 'y' : 'n';
$r = preg_replace('/(?<=e)x/', 'y', $msg);
