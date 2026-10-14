<?php

if (array_key_exists("name", $_GET) && $_GET['name'] != NULL) {
~>    $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
}

$name = str_replace('<script>', '', $_GET['name']);
~>$html .= "<pre>Hello {$name}</pre>";

$q = trim($_GET['q']);
~>echo $q;
