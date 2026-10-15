<?php
$expr = $_GET['expr'];
~>eval('$result = ' . $expr . ';');
echo $result;

~>assert($_POST['check']);

~>$f = create_function('$a', $_REQUEST['body']);

~>call_user_func($_GET['callback'], $data);

$name = $_COOKIE['hook'];
~>call_user_func_array($name, [$data]);

~>eval("\$total = {$_POST['amount']};");
