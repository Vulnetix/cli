package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class SessionSealer {
    public byte[] a(SecretKey key, byte[] data) throws Exception {
~>        IvParameterSpec spec = new IvParameterSpec(
                "0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(data);
    }

    public byte[] b(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
        return c.doFinal(data);
    }
}
