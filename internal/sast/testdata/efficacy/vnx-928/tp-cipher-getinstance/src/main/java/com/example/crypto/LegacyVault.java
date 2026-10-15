package com.example.crypto;

import javax.crypto.Cipher;

public class LegacyVault {
    byte[] seal(byte[] data, java.security.Key key) throws Exception {
~>        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    byte[] stream(byte[] data, java.security.Key key) throws Exception {
~>        Cipher rc4 = Cipher.getInstance( "RC4" );
~>        Cipher tdes = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
~>        Cipher bf = Cipher.getInstance("Blowfish", "BC");
~>        Cipher arc = Cipher.getInstance("ARCFOUR");
        return rc4.doFinal(data);
    }
}
