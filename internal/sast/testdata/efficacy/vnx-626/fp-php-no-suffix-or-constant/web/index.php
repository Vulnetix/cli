<?php
include __DIR__ . '/config.php';
require_once 'lib/' . $module . '.php';
$data = file_get_contents('https://api.example.com/v1/' . $endpoint . '.json');
echo htmlspecialchars($_GET['page'] . '.php');
