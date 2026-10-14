package com.example.crypto;

import java.util.Properties;
import javax.crypto.Cipher;

public final class LegacyStore {
    Cipher fromConfig(Properties props) throws Exception {
        String alg = props.getProperty("cipher", "AES/ECB/PKCS5Padding");
        return Cipher.getInstance(alg);
    }

    Cipher tripleDes() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }

    Cipher blowfish() throws Exception {
        return Cipher.getInstance("Blowfish");
    }
}
