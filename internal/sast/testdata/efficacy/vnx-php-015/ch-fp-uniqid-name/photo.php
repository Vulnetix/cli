<?php
$original = $_FILES['photo']['name'];
log_upload($original);
move_uploaded_file($_FILES['photo']['tmp_name'], $dir . '/' . uniqid('p', true) . '.jpg');
