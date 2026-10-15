<?php
$message = trim($_POST['mtxMessage']);
~>$message = preg_replace('/<script>/', '', $message);
$query = "INSERT INTO guestbook (comment) VALUES ('" . $message . "')";
