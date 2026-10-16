<?php
if (isset($_POST['ip'])) {
    $target = trim($_POST['ip']);
~>    $substitutions = array('&&' => '', ';' => '');
    $target = str_replace(array_keys($substitutions), $substitutions, $target);
    $cmd = shell_exec('ping -c 4 ' . $target);
    echo "<pre>{$cmd}</pre>";
}
