<?php

// never write: if (md5($x) == $hash) because "0e123" == "0e456" is true
$t = 'if (strcmp($_POST["k"], $s) == 0)';
echo password_verify($_POST['p'], $stored) ? 'ok' : 'no';
