<?php
$cookie_value = md5(uniqid());
~>setcookie("appSession", $cookie_value);
