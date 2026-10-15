package com.acme;

import javax.crypto.Cipher;

public class Vault {
    public byte[] seal(byte[] k, byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance("DESede");
        return c.doFinal(d);
    }

    public byte[] seal2(byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
        return c.doFinal(d);
    }
}
