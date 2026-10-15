package com.acme.crypto;

import java.util.Date;

public final class KeyHolder {
    private final byte[] key;
    private final Date notAfter;

    public KeyHolder(byte[] key,
                     Date notAfter) {
~>        this.key = key;
~>        this.notAfter = notAfter;
    }

    protected void rotate(char pin[]) {
~>        this.pin = pin;
    }

    private char[] pin;
}
