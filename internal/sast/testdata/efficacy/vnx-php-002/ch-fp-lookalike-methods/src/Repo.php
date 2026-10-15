<?php
class Repo
{
    public function purge($pdo, $redis)
    {
        $pdo->exec("DELETE FROM sessions WHERE id = " . $pdo->quote($_GET['sid']));
        $ch = curl_init('https://status.example.com');
        $body = curl_exec($ch);
        $redis->eval('return redis.call("get", KEYS[1])', [$_GET['key']], 1);
        $this->system($_POST['name']);
        Shell::exec($_REQUEST['task']);
    }
}
