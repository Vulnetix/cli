package com.acme;

import javax.crypto.Cipher;

public class Sealer {
~>    private Cipher cipher;

    public byte[] seal(byte[] data) throws Exception {
        return this.cipher.doFinal(data);
    }
}
