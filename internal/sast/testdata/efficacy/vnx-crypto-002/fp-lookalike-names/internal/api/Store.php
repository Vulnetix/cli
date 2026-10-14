<?php

class Store
{
    public function sha1($value)
    {
        return hash('sha256', $value);
    }

    public function both($v)
    {
        return [$this->sha1($v), self::sha1($v)];
    }
}

function sha1_column($row) {
    return $row['sha1'];
}
