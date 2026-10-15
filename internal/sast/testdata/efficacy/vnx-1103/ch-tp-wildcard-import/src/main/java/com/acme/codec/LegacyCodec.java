package com.acme.codec;

~>import sun.misc.*;
~>import static jdk.internal.misc.Unsafe.getUnsafe;

public class LegacyCodec {
    public String encode(byte[] data) {
        return new BASE64Encoder().encode(data);
    }
}
