<?php
// Old code was: include($_GET['page'] . '.php'); now routed through the router.
$msg = "never include(\$_GET['page'] . '.php')";
echo $msg;
