package com.acme.crypto;

import java.util.Properties;
import javax.crypto.Cipher;

public class Vault {
    Cipher cipher(Properties props) throws Exception {
        String transformation = props.getProperty("cipher.transformation", "AES/ECB/PKCS5Padding");
~>        return Cipher.getInstance(transformation);
    }

    Cipher other(Properties props) throws Exception {
        String alg = props.getProperty("legacy.alg", "AES/ECB/NoPadding");
~>        return Cipher.getInstance(alg);
    }
}
