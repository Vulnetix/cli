<?php
$out = shell_exec("/usr/bin/pg_dump -Fc mydb > /var/backups/mydb.dump");
system("df -h /var");
exec("uptime", $lines);
