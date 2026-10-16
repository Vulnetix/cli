<?php
$pin = $_POST['pin'];
~>setcookie('kiosk_pin', $pin, time() + 3600, '/', '', true, true);
header('Location: /kiosk/menu.php');
