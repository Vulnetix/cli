package com.acme.codec;

public class CodecRegistry {
    private final ClassLoader loader;

    public CodecRegistry(ClassLoader loader) {
        this.loader = loader;
    }

    public Codec lookup(String format) throws Exception {
~>        Class<?> c = loader.loadClass(String.format("com.acme.codec.%sCodec", capitalize(format)));
        return (Codec) c.getDeclaredConstructor().newInstance();
    }

    public Codec lookupVersioned(String format, int version) throws Exception {
        String name = "com.acme.codec.v%d.%sCodec".formatted(version, format);
~>        Class<?> c = loader.loadClass(name);
        return (Codec) c.getDeclaredConstructor().newInstance();
    }

    public Codec lookupWrapped(String format) throws Exception {
~>        Class<?> c = loader.loadClass("com.acme.codec."
                + format + "Codec");
        return (Codec) c.getDeclaredConstructor().newInstance();
    }

    private static String capitalize(String s) {
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
