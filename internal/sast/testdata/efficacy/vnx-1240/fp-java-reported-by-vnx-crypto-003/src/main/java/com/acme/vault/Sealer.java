package com.acme.vault;

import javax.crypto.Cipher;

// Java ECB that VNX-CRYPTO-003 reports is one finding, not two.
public class Sealer {
    private static final String MODE = "AES/ECB/PKCS5Padding";

    Cipher explicit() throws Exception {
        return Cipher.getInstance("AES/ECB/NoPadding");
    }

    Cipher bare() throws Exception {
        return Cipher.getInstance("AES");
    }

    Cipher constant() throws Exception {
        return Cipher.getInstance(MODE);
    }

    Cipher split() throws Exception {
        return Cipher.getInstance(
                "DESede/ECB/PKCS5Padding");
    }
}
