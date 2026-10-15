<?php
$name = $_GET['name'];
$safe = htmlspecialchars($name, ENT_QUOTES);
echo "<p>" . $safe . "</p>";
echo htmlspecialchars($name);
