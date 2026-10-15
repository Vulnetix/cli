<?php
echo "Never call ini_set('session.use_trans_sid', 1) in production";
$doc = ['use_only_cookies' => 0];
