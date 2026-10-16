<?php

$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['jpg', 'png', 'gif'], true)) {
    die('type not allowed');
}
$dest = 'uploads/' . md5_file($_FILES['f']['tmp_name']) . '.' . $ext;
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
