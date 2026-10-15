<?php
$name = $_POST['name'];
$sql = "SELECT id, email FROM users "
     . "WHERE name = '" . $name . "' "
     . "ORDER BY id";
~>$result = $conn->query($sql);

~>$res = mysqli_query(
    $conn,
    "DELETE FROM sessions WHERE token = '" . $_COOKIE['tok'] . "'"
);
