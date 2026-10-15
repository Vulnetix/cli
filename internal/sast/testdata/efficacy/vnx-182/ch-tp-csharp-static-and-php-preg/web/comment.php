<?php
$message = $_POST['message'];
~>$message = preg_replace('/<script>/i', '', $message);
echo "<p>" . $message . "</p>";
