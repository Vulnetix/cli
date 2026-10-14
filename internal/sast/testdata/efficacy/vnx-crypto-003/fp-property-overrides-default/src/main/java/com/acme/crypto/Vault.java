package com.acme.crypto;

import java.util.Properties;
import javax.crypto.Cipher;

public class Vault {
    private final Properties props;

    Vault(Properties props) {
        this.props = props;
    }

    Cipher cipher() throws Exception {
        String transformation = props.getProperty("cipher.transformation", "AES/ECB/PKCS5Padding");
        return Cipher.getInstance(transformation);
    }
}
