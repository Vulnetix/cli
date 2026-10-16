<?php
$name = $_REQUEST['name'];
header('Content-Type: text/html');
~>echo file_get_contents("templates/" . $name . ".html");
