<?php

class Database
{
    public static function pdo(string $user, string $pass): PDO
    {
~>        return new PDO('mysql:host=10.0.0.21;dbname=shop;charset=utf8mb4', $user, $pass);
    }

    public static function legacy(string $user, string $pass)
    {
~>        return mysqli_connect("192.168.10.4", $user, $pass, "shop");
    }

    public static function reports(string $user, string $pass): mysqli
    {
~>        return new mysqli('reports.db.acme-corp.com', $user, $pass, 'reports');
    }
}
