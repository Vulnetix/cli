<?php
$cookie_value = md5(uniqid());
// Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
setcookie("appSession", $cookie_value);
