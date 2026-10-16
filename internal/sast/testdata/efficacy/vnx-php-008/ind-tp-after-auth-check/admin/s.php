<?php
session_start();
if (!empty($_SESSION['user'])) {
    echo "<h1>Server</h1>";
~>    phpinfo();
}
