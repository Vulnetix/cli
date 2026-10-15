package org.shop;

import org.springframework.beans.factory.annotation.Value;

public class Cache {
~>    @Value("${redis.password:abc123}")
    private String redisPassword;
}
