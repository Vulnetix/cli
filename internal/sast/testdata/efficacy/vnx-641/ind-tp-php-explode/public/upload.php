<?php
$name = $_FILES['avatar']['name'];
~>$ext = explode('.', $name)[1];
if (in_array($ext, ['png', 'jpg'])) {
    move_uploaded_file($_FILES['avatar']['tmp_name'], "uploads/" . $name);
}
