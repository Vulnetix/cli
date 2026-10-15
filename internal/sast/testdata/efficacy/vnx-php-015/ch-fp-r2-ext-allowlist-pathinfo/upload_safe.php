<?php
$ext = strtolower(pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['jpg', 'png', 'gif'], true)) {
    die('Invalid type');
}
$dest = 'uploads/' . bin2hex(random_bytes(8)) . '.' . $ext;
move_uploaded_file($_FILES['doc']['tmp_name'], $dest);
