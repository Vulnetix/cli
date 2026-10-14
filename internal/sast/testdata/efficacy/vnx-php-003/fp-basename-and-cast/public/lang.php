<?php
$lang = basename($_GET["lang"]);
include "lang/" . $lang . ".php";
include "steps/step" . (int) $_GET["step"] . ".php";
include "pages/" . basename($_REQUEST["p"]) . ".php";
