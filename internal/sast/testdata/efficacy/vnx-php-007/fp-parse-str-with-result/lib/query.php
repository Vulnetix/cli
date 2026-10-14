<?php
parse_str($_SERVER["QUERY_STRING"], $params);
$qs = $_GET["q"];
parse_str($qs, $parts);
mb_parse_str($_POST["payload"], $result);
