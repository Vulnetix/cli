<?php
~>parse_str($_SERVER['QUERY_STRING']);
if ($authenticated) {
    show_dashboard();
}

$qs = $_GET['state'];
~>parse_str( $qs );
