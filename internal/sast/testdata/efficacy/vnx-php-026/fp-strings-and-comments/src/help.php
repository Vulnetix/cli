<?php
// Never write $_SESSION[$_GET['key']] = $value; it lets a client set any key.
/*
 * $_SESSION = array_merge($_SESSION, $_POST); is the same bug.
 */
# foreach ($_POST as $k => $v) { $_SESSION[$k] = $v; }

$doc = 'Avoid $_SESSION[$_POST["k"]] = 1 in handlers';
echo "Example: \$_SESSION[\$_GET['x']] = 1";
