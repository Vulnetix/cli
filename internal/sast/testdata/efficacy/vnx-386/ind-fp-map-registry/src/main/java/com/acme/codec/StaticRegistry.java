package com.acme.codec;

import java.util.Map;

public final class StaticRegistry {
    private static final Map<String, Class<? extends Codec>> CODECS = Map.of(
            "gzip", GzipCodec.class,
            "zstd", ZstdCodec.class);

    public Codec lookup(String name) throws ReflectiveOperationException {
        Class<? extends Codec> type = CODECS.get(name);
        if (type == null) {
            throw new IllegalArgumentException(name);
        }
        return type.getDeclaredConstructor().newInstance();
    }
}
