<?php
~>$file = str_replace(array("../", "..\\"), "", $_GET['page']);
include "pages/" . $file;

~>$name = preg_replace('/<script>/i', '', $_POST['name']);
echo "Hello " . $name;
