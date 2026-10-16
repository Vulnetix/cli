<?php
$name = basename($_GET["page"]);
include __DIR__ . "/pages/" . $name . ".php";
include("partials/" . basename($_GET["p"]));
