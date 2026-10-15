<?php
$name = $_POST['name'];
~>$name = str_replace('<script>', '', $name);
~>$msg = preg_replace('/<script(.*?)>/', '', $_POST['msg']);
~>if (preg_match("/union\s+select/", $_GET['q'])) {
    die('blocked');
}
