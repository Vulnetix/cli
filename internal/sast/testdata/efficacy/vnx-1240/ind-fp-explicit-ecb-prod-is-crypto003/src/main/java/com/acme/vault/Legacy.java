package com.acme.vault;

import javax.crypto.Cipher;

public class Legacy {
    public Cipher make() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher;
    }
    public Cipher bare() throws Exception {
        return Cipher.getInstance("DESede");
    }
}
