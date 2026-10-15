<?php

$file = $_GET['file'];
~>if (strpos($file, '..') !== false) {
    die('invalid');
}
$file = urldecode($file);
readfile('/srv/files/' . $file);
