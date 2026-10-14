package com.acme.vault;

import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TokenCipher {

    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String ALGORITHM = "AES";

    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
~>        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(data);
    }

    public byte[] defaultMode(byte[] key, byte[] data) throws Exception {
        // "AES" alone resolves to AES/ECB/PKCS5Padding in the SunJCE provider.
~>        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
        return cipher.doFinal(data);
    }

    public byte[] withProvider(byte[] key, byte[] data) throws Exception {
~>        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding", "BC");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
        return c.doFinal(data);
    }

    public byte[] constant(byte[] key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
        return c.doFinal(data);
    }

    public byte[] defaultConstant(byte[] key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM));
        return c.doFinal(data);
    }

    public byte[] configured(Properties props, byte[] key, byte[] data) throws Exception {
        String algorithm = props.getProperty("cipher.transformation", "AES/ECB/PKCS5Padding");
~>        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }

    public byte[] wrapped(byte[] key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance(
                "AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }
}
