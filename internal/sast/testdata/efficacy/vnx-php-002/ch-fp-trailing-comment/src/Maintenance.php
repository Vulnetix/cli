<?php
$status = 0;
$out = shell_exec('uptime'); // never shell_exec($_GET['cmd']) here
$files = glob('/tmp/*.lock'); # was system($_REQUEST['x'])
