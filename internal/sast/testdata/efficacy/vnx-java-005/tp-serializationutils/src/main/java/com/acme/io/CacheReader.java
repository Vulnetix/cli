package com.acme.io;

import org.apache.commons.lang3.SerializationUtils;

public class CacheReader {
    public Object read(byte[] fromRedis) {
~>        return SerializationUtils.deserialize(fromRedis);
    }
}
