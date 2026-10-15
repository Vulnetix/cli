<?php

class Store
{
    public function path($key)
    {
        $parts = array_slice(str_split($hash = sha1($key), 2), 0, 2);
        return $this->directory.'/'.implode('/', $parts).'/'.$hash;
    }

    public function sessionName()
    {
        return 'login_'.$this->name.'_'.sha1(static::class);
    }

    public function rememberName()
    {
        return 'remember_'.sha1(__CLASS__);
    }
}
