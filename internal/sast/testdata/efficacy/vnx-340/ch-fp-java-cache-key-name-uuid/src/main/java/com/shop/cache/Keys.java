package com.shop.cache;

import java.util.UUID;

public class Keys {
    public static String cacheKey(String path) {
        String cacheKey = UUID.nameUUIDFromBytes(path.getBytes()).toString();
        return cacheKey;
    }

    public static String sessionToken() {
        String sessionToken = UUID.randomUUID().toString();
        return sessionToken;
    }
}
