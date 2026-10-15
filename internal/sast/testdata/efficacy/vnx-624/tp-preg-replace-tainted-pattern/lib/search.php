<?php
~>$out = preg_replace($_GET['pattern'], $_GET['replace'], $content);

$find = $_POST['find'];
$with = $_POST['with'];
~>echo preg_replace($find, $with, $doc);
