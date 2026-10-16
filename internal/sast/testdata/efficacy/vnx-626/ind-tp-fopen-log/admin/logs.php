<?php
$logDir = '/var/log/app/';
~>$fh = fopen($logDir . $_POST['day'] . '.log', 'r');
while (($line = fgets($fh)) !== false) {
    echo htmlspecialchars($line);
}
fclose($fh);
