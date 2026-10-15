package com.acme.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;

public class StreamCipher {
    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        IvParameterSpec spec = new IvParameterSpec(new byte[cipher.getBlockSize()]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }

    public byte[] sealGcm(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key,
~>                new GCMParameterSpec(128,
                        new byte[12]));
        return cipher.doFinal(data);
    }
}
