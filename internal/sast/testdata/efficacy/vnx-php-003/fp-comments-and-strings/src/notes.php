<?php
// include($_GET["page"]) would be file inclusion
# require $_POST["x"];
/* include_once $_REQUEST["m"]; */
echo "Never include \$_GET[page] directly";
$doc = 'include $_GET["page"];';
$this->include($_GET["partial"]);
