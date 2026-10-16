package com.harbourline.ferry.security;

import android.security.keystore.KeyProperties;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

final class KeystoreCipher {

    byte[] wrap(Key key, byte[] payload) throws GeneralSecurityException {
~>        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_ECB + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(payload);
    }

    byte[] unwrap(Key key, byte[] payload) throws GeneralSecurityException {
~>        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(payload);
    }
}
