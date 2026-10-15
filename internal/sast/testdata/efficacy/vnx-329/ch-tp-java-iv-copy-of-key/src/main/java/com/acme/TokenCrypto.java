package com.acme;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class TokenCrypto {
    public byte[] encrypt(SecretKey secretKey, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOf(secretKey.getEncoded(), 16));
        c.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return c.doFinal(plain);
    }
}
