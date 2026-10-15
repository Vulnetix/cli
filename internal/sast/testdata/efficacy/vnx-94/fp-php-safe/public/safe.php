<?php
$n = $_GET['n'];
eval('$result = ' . intval($_GET['n']) . ';');
call_user_func([$this, 'handle'], $_GET['x']);
call_user_func('strtoupper', $_POST['name']);
assert($count > 0);
// eval($_GET['code']);
$message = "eval(\$_GET['code']) is forbidden";
$allowed = ['add' => fn($a, $b) => $a + $b];
$op = $_POST['op'];
if (array_key_exists($op, $allowed)) {
    echo $allowed[$op](1, 2);
}
