<?php

class SessionGuard
{
    public function getName()
    {
        return 'login_'.$this->name.'_'.sha1(static::class);
    }

    public function outputPath()
    {
        return storage_path('logs/schedule-'.sha1($this->mutexName()).'.log');
    }

    public function taggedKey($key)
    {
        return sha1($this->tags->getNamespace()).':'.$key;
    }
}
