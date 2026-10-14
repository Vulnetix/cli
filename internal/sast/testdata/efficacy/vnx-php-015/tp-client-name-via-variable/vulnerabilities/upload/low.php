<?php

if (isset($_POST['Upload'])) {
    $target_path  = ROOT . "hackable/uploads/";
    $target_path .= basename($_FILES['uploaded']['name']);

~>    if (!move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)) {
        echo '<pre>Your image was not uploaded.</pre>';
    }
}

$name = $_FILES['report']['name'];
$dest = UPLOAD_DIR . '/' . $name;
~>move_uploaded_file($_FILES['report']['tmp_name'], $dest);
