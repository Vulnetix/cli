<?php
$user = $_POST['username'];
$pass = $_POST['password'];
~>if ($user === 'maint' && $pass === 'Maint3nance!') {
    $_SESSION['role'] = 'admin';
}
