package com.acme.codec;

import java.util.Map;

public final class Registry {
    private static final Map<String, String> IMPLS = Map.of("json", "com.acme.codec.JsonCodec", "xml", "com.acme.codec.XmlCodec");
    private static final Map<String, Class<? extends Codec>> TYPES = Map.of("json", JsonCodec.class);

    public Class<?> impl() throws ClassNotFoundException {
        return getClass().getClassLoader().loadClass(getClass().getPackage().getName() + ".Impl");
    }

    public Class<?> byKey(String key) throws ClassNotFoundException {
        String impl = IMPLS.get(key);
        if (impl == null) {
            throw new IllegalArgumentException("unknown codec");
        }
        return Class.forName(impl);
    }

    public Class<? extends Codec> typed(String key) {
        return TYPES.get(key);
    }

    public Class<?> fixed() throws ClassNotFoundException {
        return Class.forName("com.acme." + "codec.JsonCodec");
    }
}
