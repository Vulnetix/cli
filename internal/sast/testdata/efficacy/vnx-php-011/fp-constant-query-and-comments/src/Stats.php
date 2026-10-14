<?php

// mysqli_query($conn, "SELECT * FROM t WHERE id = " . $_GET['id']);
/* $pdo->query("... $_POST[name]") was removed */

function stats($conn)
{
    $table = 'orders';
    $res = mysqli_query($conn, "SELECT COUNT(*) FROM $table");
    $all = $conn->query('SELECT * FROM users WHERE name = $_GET');
    $help = "never call mysql_query() with \$_GET values";
    return [$res, $all, $help];
}

$builder = DB::table('users')->where('id', $_GET['id'])->get();
