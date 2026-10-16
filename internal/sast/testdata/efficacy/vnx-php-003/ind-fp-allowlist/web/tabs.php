<?php
$tab = $_GET["tab"];
if (!in_array($tab, ["profile", "billing", "security"], true)) {
    $tab = "profile";
}
require __DIR__ . "/tabs/" . $tab . ".php";
