<?php
$name = $_FILES['doc']['name'];
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (preg_match('/\.(pdf|docx)$/i', $name) && in_array($ext, ['pdf', 'docx'])) {
    move_uploaded_file($_FILES['doc']['tmp_name'], 'u/' . bin2hex(random_bytes(8)) . '.' . $ext);
}
