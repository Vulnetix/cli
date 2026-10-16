<?php
$file = $_GET['file'];
~>$h = popen("convert " . $file . " out.png", "r");
pclose($h);
