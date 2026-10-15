<?php
session_start();
$log = 'sid=' . session_id() . ' user=' . $_GET['user'];
if (session_id() === '') {
    session_id(session_create_id('app-'));
}
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', 0);
