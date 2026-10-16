<?php
$back = $_SERVER["HTTP_REFERER"];
~>header("Location: $back");
exit;
