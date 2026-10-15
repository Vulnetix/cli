package com.acme.crypto;

import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class ConfiguredCipher {
    private final Properties props;

    public ConfiguredCipher(Properties props) {
        this.props = props;
    }

    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        String algorithm = props.getProperty("crypto.alg", "DESede/ECB/PKCS5Padding");
~>        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] sealGcm(SecretKey key, byte[] data) throws Exception {
        String mode = props.getProperty("crypto.mode", "AES/GCM/NoPadding");
        Cipher c = Cipher.getInstance(mode);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
