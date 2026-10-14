<?php

// session_id($_GET['sid']) lets attackers fix the session
/* session_id($_COOKIE['x']); */
$help = "never call session_id(\$_GET['sid'])";
