package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class BlobWriter {
    public byte[] write(SecretKey key, byte[] blob) throws Exception {
        Cipher cipher =
            Cipher.getInstance(
~>                "AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(blob);
    }
}
