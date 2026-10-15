<?php
setcookie("password", "", time() - 3600, "/");
setcookie("PHPSESSID", session_id(), 0, "/", "", true, true);
