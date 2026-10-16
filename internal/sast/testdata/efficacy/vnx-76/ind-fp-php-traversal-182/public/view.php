<?php
$file = $_GET['page'];
$file = str_replace(array("../", "..\\"), "", $file);

$name = str_replace('<script>', '', $_GET['name']);
$link = str_replace('javascript:', '', $_GET['link']);

include 'pages/' . $file;
