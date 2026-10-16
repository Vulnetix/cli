package com.acme;

import java.io.DataInputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Stream {
    Cipher open(DataInputStream in, SecretKey k) throws Exception {
        byte[] iv = new byte[16];
        in.readFully(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
        return c;
    }
}
