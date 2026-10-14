<?php
$is_admin = false;
~>extract($_POST);
~>extract( $_GET , EXTR_OVERWRITE );
~>extract($_REQUEST, EXTR_SKIP);
~>\extract($_COOKIE);
if ($is_admin) {
    show_admin_panel();
}
