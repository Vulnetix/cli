<?php
$domain = $_REQUEST['domain'];
~>$domain = str_replace(array(';', '&&', '|', '`'), '', $domain);
echo shell_exec('nslookup ' . $domain);
