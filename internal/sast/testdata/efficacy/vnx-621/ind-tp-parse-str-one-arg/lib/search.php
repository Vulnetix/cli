<?php
function load_filters() {
    $show_deleted = 0;
~>    parse_str($_SERVER['QUERY_STRING']);
    return $show_deleted;
}
