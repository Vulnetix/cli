<?php

$uploaded_name = $_FILES['uploaded']['name'];
$uploaded_ext  = substr($uploaded_name, strrpos($uploaded_name, '.') + 1);
$uploaded_tmp  = $_FILES['uploaded']['tmp_name'];
$target_path   = "uploads/" . basename($uploaded_name);

if ((strtolower($uploaded_ext) == "jpg" || strtolower($uploaded_ext) == "png") && getimagesize($uploaded_tmp)) {
    move_uploaded_file($uploaded_tmp, $target_path);
}

$ext = strtolower(pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION));
$allowed = ['pdf', 'txt'];
if (!in_array($ext, $allowed, true)) {
    exit('bad type');
}
move_uploaded_file($_FILES['doc']['tmp_name'], 'docs/' . $_FILES['doc']['name']);
