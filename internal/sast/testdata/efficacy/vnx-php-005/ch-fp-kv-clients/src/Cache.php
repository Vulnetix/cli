<?php
class Cache
{
    public function read()
    {
        $value = $this->redisClient->get($_GET['key']);
        $hit = $memcacheClient->get('user:' . $_COOKIE['uid']);
        $doc = $this->mongoClient->get($_POST['id']);
        return [$value, $hit, $doc];
    }
}
