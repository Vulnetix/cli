<?php

$fh = fopen($_FILES['csv']['tmp_name'], 'r');
while (($line = fgets($fh)) !== false) {
~>    $cols = explode(',', trim($line));
    insert_contact($cols[0], $cols[1]);
}
fclose($fh);
