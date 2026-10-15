<?php
$file = $_GET['file'];
$file = str_replace(array("http://", "https://"), "", $file);
$file = str_replace(array("../", "..\\"), "", $file);
~>include($file);
