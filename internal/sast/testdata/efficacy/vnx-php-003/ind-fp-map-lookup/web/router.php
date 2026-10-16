<?php
$pages = ["home" => "home.php", "about" => "about.php"];
include $pages[$_GET["p"]];
