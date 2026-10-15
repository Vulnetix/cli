<?php

$target = $_REQUEST['ip'];

// strip shell separators
~>$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace(array_keys($substitutions), $substitutions, $target);

$cmd = shell_exec('ping -c 4 ' . $target);
echo "<pre>{$cmd}</pre>";
