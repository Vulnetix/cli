<?php
session_start();

foreach ($_POST as $k => $v) {
~>    $_SESSION[$k] = $v;
}

foreach ($_GET as $param => $val)
{
    if ($val === '') {
        continue;
    }
~>    $_SESSION[$param] = htmlspecialchars($val);
}
