package com.acme.auth;

import redis.clients.jedis.Jedis;

public class PendingLogin {
    private final Jedis jedis = new Jedis("cache.internal", 6379);

    public void stash(String userId, String password) {
~>        jedis.setex("pending:" + userId, 300, password);
    }
}
