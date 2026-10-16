<?php
$content = file_get_contents('page.txt');
~>$out = preg_replace($_POST['pattern'], $_POST['with'], $content);
echo $out;
