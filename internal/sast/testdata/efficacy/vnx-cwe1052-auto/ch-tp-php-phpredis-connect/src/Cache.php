<?php

namespace App;

final class Cache
{
    private \Redis $redis;

    public function __construct()
    {
        $this->redis = new \Redis();
~>        $this->redis->connect('10.12.0.9', 6379, 2.5);
~>        $this->redis->pconnect("@@sample:c[a]ch[e][-]0[1][.]p[r]od[.]ac[m]e[-][c]or[p][.]n[e]t@@");
    }
}
