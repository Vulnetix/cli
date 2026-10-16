<?php
$db = null;
$log = null;
$conf = array();

function db_query($sql) {
~>    global $db;
    return $db->query($sql);
}

function db_log($msg) {
~>    global $log;
    $log->write($msg);
}

function db_conf($key) {
~>    global $conf;
    return $conf[$key];
}
