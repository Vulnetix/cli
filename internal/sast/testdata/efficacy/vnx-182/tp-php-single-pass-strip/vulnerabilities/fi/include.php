<?php

$file = $_GET['page'];

// strip remote schemes and traversal before including
~>$file = str_replace( array( "http://", "https://" ), "", $file );
~>$file = str_replace(array("../", "..\\"), '', $file);

include($file);

$name = $_POST['name'];
~>$name = str_ireplace('<script>', '', $name);
echo "Hello " . $name;
