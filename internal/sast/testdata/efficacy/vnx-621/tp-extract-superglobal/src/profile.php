<?php
function update_profile() {
~>    extract($_POST);
    $is_admin = isset($is_admin) ? $is_admin : false;
    save_user($name, $email, $is_admin);
}

function search() {
~>    extract( $_GET , EXTR_SKIP );
    return find_items($q);
}

function settings() {
~>    extract($_REQUEST, EXTR_OVERWRITE);
}
