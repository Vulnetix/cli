<?php
$pages = ["home" => "home.php", "about" => "about.php"];
$page = $_GET["page"] ?? "home";
if (!isset($pages[$page])) {
    $page = "home";
}
include $pages[$page];

$section = $_GET["section"];
if (!in_array($section, ["news", "blog"], true)) {
    exit;
}
include "sections/" . $section . ".php";
