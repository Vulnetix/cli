<?php
$host = $_POST["host"];
~>$out = shell_exec("ping -c 3 " . $host);
echo "<pre>$out</pre>";
