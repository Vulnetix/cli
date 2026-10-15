<?php

$fh = fopen($_FILES['csv']['tmp_name'], 'r');
while (($cols = fgetcsv($fh)) !== false) {
    insert_contact($cols[0], $cols[1]);
}
$ids = explode(',', $_GET['ids']);
