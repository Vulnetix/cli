<?php

// session_id($_GET['sid']); would allow fixation
$x = "ini_set('session.use_trans_sid', 1)";
$sid = $_GET['page'];
echo session_id();
