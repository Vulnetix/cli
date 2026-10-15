<?php
$page = $_GET['page'];
if (isset($page)) {
~>    include($page);
}

$section = filter_input(INPUT_GET, 'section');
$path = __DIR__ . '/sections/' . $section;
~>require_once $path;
