<?php

function build_search_filters()
{
    $limit = 20;
    $params = $_GET;
~>    extract($params);

    return ['q' => $q ?? '', 'limit' => (int) $limit];
}
