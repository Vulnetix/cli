<?php
$dir = __DIR__ . '/storage/';
$target = $dir . basename($_FILES["file"]["name"]);
~>if (move_uploaded_file($_FILES["file"]["tmp_name"], $target)) {
    echo "saved";
}
