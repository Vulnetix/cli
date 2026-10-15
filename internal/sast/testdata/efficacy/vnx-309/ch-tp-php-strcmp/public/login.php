<?php
$password = $_POST['password'];
$row = $stmt->fetch(PDO::FETCH_ASSOC);
~>if ($row && strcmp($row['password'], $password) === 0) {
    $_SESSION['uid'] = $row['id'];
}
