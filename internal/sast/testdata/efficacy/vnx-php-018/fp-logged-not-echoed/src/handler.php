<?php
error_log(print_r($_SERVER, true));
$snapshot = var_export($_SESSION, true);
file_put_contents('/var/log/app/session.log', $snapshot, FILE_APPEND);
$logger->debug('request', ['server' => print_r($_SERVER, true)]);
$dumper->dump($_SERVER);
