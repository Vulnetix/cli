<?php

$current = session_id();
session_regenerate_id(true);
session_id(bin2hex(random_bytes(16)));
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.use_trans_sid', 0);
