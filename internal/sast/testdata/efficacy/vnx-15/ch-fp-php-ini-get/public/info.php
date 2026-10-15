<?php
ini_set('display_errors', '0');
$name = $_GET['setting'];
echo htmlspecialchars((string) ini_get('memory_limit'));
echo htmlspecialchars($name);
