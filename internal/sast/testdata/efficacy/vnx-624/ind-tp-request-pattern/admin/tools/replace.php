<?php
require __DIR__ . '/../auth.php';

$content = file_get_contents(__DIR__ . '/../../content/page.html');
~>$preview = preg_replace($_POST['search'], $_POST['replacement'], $content);
echo $preview;
