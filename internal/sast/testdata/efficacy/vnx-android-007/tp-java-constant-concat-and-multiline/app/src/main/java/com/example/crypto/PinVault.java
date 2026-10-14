package com.example.crypto;

import android.security.keystore.KeyProperties;
import javax.crypto.Cipher;

public class PinVault {
    private static final String TRANSFORMATION = "AES/ECB/PKCS7Padding";
    private static final String ALGORITHM = "AES";

    Cipher constant() throws Exception {
~>        return Cipher.getInstance(TRANSFORMATION);
    }

    Cipher bareConstant() throws Exception {
~>        return Cipher.getInstance(PinVault.ALGORITHM);
    }

    Cipher keyProperties() throws Exception {
~>        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_ECB + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    Cipher concatenated() throws Exception {
~>        return Cipher.getInstance(ALGORITHM + "/ECB/PKCS5Padding");
    }

    Cipher multiline() throws Exception {
~>        Cipher cipher = Cipher.getInstance(
                "AES/ECB/PKCS5Padding");
        return cipher;
    }
}
