<?php
class FileCache
{
    public function get($key)
    {
        $contents = file_get_contents($this->path($key));
        return unserialize(substr($contents, 10));
    }

    public function unserialize($data)
    {
        return parent::unserialize($data);
    }
}

$value = unserialize($redis->get("session:" . $_COOKIE["sid"]));
$cfg = unserialize(file_get_contents(__DIR__ . "/cache/config.ser"));
