<?php

$target = "uploads/" . basename($_FILES['uploaded']['name']);
$type = $_FILES['uploaded']['type'];
$size = $_FILES['uploaded']['size'];

if (($type == "image/jpeg" || $type == "image/png") && $size < 100000) {
~>    move_uploaded_file($_FILES['uploaded']['tmp_name'], $target);
}
