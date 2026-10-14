package com.example.crypto;

import java.security.PrivateKey;
import javax.crypto.Cipher;

public class TokenUnwrapper {
    public byte[] unwrap(PrivateKey key, byte[] blob) throws Exception {
        // "RSA" alone resolves to RSA/ECB/PKCS1Padding in the SunJCE provider
~>        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(blob);
    }

    public byte[] legacy(PrivateKey key, byte[] blob) throws Exception {
~>        Cipher cipher = javax.crypto.Cipher.getInstance( "rsa/ecb/pkcs1padding" , "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(blob);
    }
}
