<?php

use Symfony\Component\Process\Process;

class DbCommand
{
    public function args(array $connection)
    {
        return [
            'user' => '--user='.$connection['username'],
~>            'password' => '--password='.$connection['password'],
        ];
    }

    public function dump($pass)
    {
~>        exec("mysqldump -uroot -p$pass shop > /tmp/shop.sql");
    }
}
