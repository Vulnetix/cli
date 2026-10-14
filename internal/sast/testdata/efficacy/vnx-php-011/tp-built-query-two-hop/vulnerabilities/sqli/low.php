<?php

if (isset($_REQUEST['Submit'])) {
    $id = $_REQUEST['id'];

    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
~>    $result = mysqli_query($GLOBALS["db"], $query) or die('<pre>error</pre>');

    $sort = $_COOKIE['sort'];
    $sql = "SELECT * FROM orders";
    $sql .= " ORDER BY " . $sort;
~>    $rows = mysqli_query($GLOBALS["db"], $sql);
}
