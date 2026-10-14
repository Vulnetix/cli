<?php

function report($conn)
{
    $year = $_GET['year'];
~>    $res = pg_query($conn, "SELECT * FROM sales WHERE year = " . $year);
    return pg_fetch_all($res);
}

function legacy($sqlite)
{
    $tag = $_GET['tag'];
    $q = "SELECT * FROM posts WHERE tag = '$tag'";
~>    return $sqlite->query($q);
}
