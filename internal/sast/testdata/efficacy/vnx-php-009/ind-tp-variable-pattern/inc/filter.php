<?php

$pattern = "/(" . preg_quote($word, '/') . ")/ei";
$replacement = 'highlight("\\1")';
~>$out = preg_replace($pattern, $replacement, $_GET['q']);
echo $out;
