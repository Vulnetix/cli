<?php
~>ini_set('session.use_trans_sid', 'On');
~>session_start(['use_strict_mode' => false, 'cookie_httponly' => true]);
session_start([
~>    'use_only_cookies' => 0,
]);
