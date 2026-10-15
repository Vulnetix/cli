package com.acme.codec;

public class CodecRegistry {
    public Codec codec(String format) throws Exception {
~>        Class<?> k = getClass().getClassLoader().loadClass(String.format("com.acme.codec.%sCodec", format));
        return (Codec) k.getDeclaredConstructor().newInstance();
    }

    public Codec named(String name) throws Exception {
        String className = "com.acme.codec." + name;
~>        return (Codec) Class.forName(className).getDeclaredConstructor().newInstance();
    }
}
