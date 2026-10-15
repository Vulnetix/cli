package com.acme.codec;

public interface Codec<T> {
~>    T decode(byte[] raw) throws Exception;

~>    default byte[] encode(T value) throws Exception {
        throw new UnsupportedOperationException();
    }

~>    static <T> Codec<T> forType(Class<T> type) throws ClassNotFoundException, Throwable {
        return Registry.lookup(type);
    }
}
