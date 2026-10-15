<?php
session_start();
~>echo '<pre>' . print_r($_SERVER, true) . '</pre>';
~>var_dump($_COOKIE, $_SESSION);
