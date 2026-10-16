<?php
$zip = new ZipArchive();
$zip->open("a.zip");
$zip->extractTo("/tmp/out");
$phar->extract("x");
// extract($_GET);
$s = "extract(\$_POST) is bad";
