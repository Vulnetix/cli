<?php
~>parse_str($_SERVER["QUERY_STRING"]);
$qs = $_GET["q"];
~>parse_str($qs);
~>mb_parse_str($_POST["payload"]);
~>import_request_variables("gp", "");
