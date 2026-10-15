package com.acme.sync;

import java.security.Key;

public final class LegacyBridge {

    static byte[] wrapRecord(Key k, byte[] record) throws Exception {
~>        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("Blowfish", "BC");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, k);
        return c.doFinal(record);
    }

    static byte[] unwrapRecord(Key k, byte[] blob) throws Exception {
~>        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance( "desede/ecb/pkcs5padding" );
        c.init(javax.crypto.Cipher.DECRYPT_MODE, k);
        return c.doFinal(blob);
    }
}
