<?php
foreach ($rows as $row) {
    if (in_array($row['id'], $selected)) {
        echo $row['name'];
    }
}
$cfg = json_decode(file_get_contents(__DIR__ . '/config.json'), true);
