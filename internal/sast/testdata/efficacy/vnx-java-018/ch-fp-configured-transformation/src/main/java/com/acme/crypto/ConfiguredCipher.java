package com.acme.crypto;

import javax.crypto.Cipher;

public class ConfiguredCipher {
    private final CryptoProperties props;

    public ConfiguredCipher(CryptoProperties props) {
        this.props = props;
    }

    public Cipher create() throws Exception {
        // Never use Cipher.getInstance("RSA") here: it defaults to PKCS#1 v1.5.
        String msg = "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\") is forbidden";
        return Cipher.getInstance(props.getTransformation());
    }

    public Cipher aes() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
