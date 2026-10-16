<?php
$pid = (int) $_POST["pid"];
exec("kill -TERM " . $pid);
$n = intval($_GET["n"]);
system("head -n " . $n . " /var/log/app.log");
