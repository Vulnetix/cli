package com.acme.codec;

public final class CodecFactory {
    private static final String PREFIX = "com.acme.codec.impl.";

    public Codec forKind(String kind) throws ReflectiveOperationException {
~>        Class<?> c = Class.forName(
                PREFIX + kind.toLowerCase() + "Codec");
        return (Codec) c.getDeclaredConstructor().newInstance();
    }

    public Codec forPackage(String pkg, String simple, ClassLoader loader) throws ReflectiveOperationException {
        String name = pkg + "." + simple;
~>        Class<?> c = loader.loadClass(name);
        return (Codec) c.getDeclaredConstructor().newInstance();
    }
}
