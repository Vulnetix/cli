<?php

$source = file_get_contents($path);
$source = str_replace(array('<?php', '?>'), array('&lt;?php', '?&gt;'), $source);
$url = str_replace("/vulnerabilities/api/", "", $_SERVER['REQUEST_URI']);
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo $name;
