<?php
$handle = fopen($_FILES['contacts_csv']['tmp_name'], 'r');
while (($line = fgets($handle)) !== false) {
~>    $cols = preg_split('/,/', trim($line));
    save_contact($cols[0], $cols[1], $cols[2]);
}
fclose($handle);
