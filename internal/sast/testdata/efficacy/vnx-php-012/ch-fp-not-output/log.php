<?php
error_log("bad input: " . $_GET['x']);
echo isset($_GET['debug']) ? 'on' : 'off';
echo $_SERVER['REQUEST_TIME'];
$msg = 'echo $_GET["x"] is unsafe';
// echo $_GET['name'];
