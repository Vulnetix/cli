<?php
$target = trim($_REQUEST['ip']);

$substitutions = array('&&' => '', ';' => '');
~>$target = str_replace(array('&&', ';'), '', $target);

$out = shell_exec('ping -c 4 ' . $target);
echo "<pre>{$out}</pre>";
