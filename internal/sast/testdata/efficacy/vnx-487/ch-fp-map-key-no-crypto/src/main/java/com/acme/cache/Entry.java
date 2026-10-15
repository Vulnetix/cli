package com.acme.cache;

public class Entry {
    String key;
    String cacheKey;
    Object value;
    byte[] payload;

    Entry(String key, Object value) {
        this.key = key;
        this.value = value;
    }
}
