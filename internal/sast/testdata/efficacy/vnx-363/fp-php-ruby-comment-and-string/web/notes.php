<?php
// if (!is_link($f)) { file_put_contents($f, $x); } is racy
$doc = "check is_link(\$f) then file_put_contents(\$f) is racy";
echo $doc;
