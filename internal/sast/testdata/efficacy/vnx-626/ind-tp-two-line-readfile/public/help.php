<?php
$topic = $_GET['topic'];
header('Content-Type: text/html; charset=utf-8');
~>readfile("help/{$topic}.html");
