<?php
$flags = $_GET['flags'];
~>$out = mb_eregi_replace('foo', 'bar', $text, $flags);
echo $out;
