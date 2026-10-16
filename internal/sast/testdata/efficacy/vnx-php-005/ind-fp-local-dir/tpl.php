<?php
$name = $_GET["name"];
$body = file_get_contents(__DIR__ . "/templates/" . basename($name));
$in = file_get_contents("php://input");
