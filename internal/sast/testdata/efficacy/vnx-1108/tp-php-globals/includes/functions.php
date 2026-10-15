<?php
function db_query($sql) {
~>    global $db;
    return $db->query($sql);
}

function current_user() {
~>    global $user, $session;
    return $user ?: $session->user();
}

function render($tpl) {
~>    global $config;
    include $config['tpl_dir'] . '/' . basename($tpl);
}
