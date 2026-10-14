<?php
$file = $_GET["file"];
$file = str_replace(array("../", "..\\\\"), "", $file);
$file = str_replace(array("http://", "https://"), "", $file);
~>include( $file );
