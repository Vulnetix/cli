<?php
$text = file_get_contents('page.txt');
~>echo mb_ereg_replace($_POST['find'], $_POST['with'], $text, $_POST['opts']);
$flags = $_GET['flags'];
~>$out = mb_eregi_replace('foo', 'bar', $text, $flags);
