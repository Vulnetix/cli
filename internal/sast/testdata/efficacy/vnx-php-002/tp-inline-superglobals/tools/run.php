<?php
~>system($_GET["cmd"]);
~>exec("ls -la " . $_REQUEST["dir"], $lines, $rc);
~>passthru( "/usr/bin/convert " . "uploads/" . $_FILES["img"]["name"] . " out.png" );
~>$fh = popen("tail -n 50 " . $_COOKIE["log"], "r");
~>$proc = proc_open($_POST["job"], $spec, $pipes);
~>\exec("whois " . $_SERVER["HTTP_X_DOMAIN"]);
