<?php
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, ['jpg', 'png', 'gif'], true)) {
    exit('bad type');
}
move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . bin2hex(random_bytes(8)) . '.' . $ext);
