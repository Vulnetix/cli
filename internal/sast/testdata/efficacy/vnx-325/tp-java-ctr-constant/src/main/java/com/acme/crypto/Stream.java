package com.acme.crypto;

import javax.crypto.Cipher;

public final class Stream {
~>    private static final String TRANSFORMATION = "AES/CTR/NoPadding";

    public Cipher cipher() throws Exception {
        return Cipher.getInstance(TRANSFORMATION);
    }
}
