<?php
$body = file_get_contents('page.html');
~>$body = preg_replace('/' . $_POST['find'] . '/', $_POST['replace'], $body);
~>$out = preg_replace("/{$_GET['term']}/i", '<mark>$0</mark>', $body);
echo $out;
