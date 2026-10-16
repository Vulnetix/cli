<?php
$file = $_GET['page'] ?? 'home';
~>$file = str_replace(array("../", "..\\"), '', $file);
include __DIR__ . '/pages/' . $file . '.php';

$name = $_POST['name'] ?? '';
~>$name = str_ireplace('<script>', '', $name);
echo "<p>Hello " . $name . "</p>";
