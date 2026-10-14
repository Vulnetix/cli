<?php

class Repo
{
    public function md5($value)
    {
        return hash('sha256', $value);
    }

    public function check($a)
    {
        return $this->md5($a) === static::md5($a);
    }
}

function md5_lookup($row) {
    return $row['md5'];
}
