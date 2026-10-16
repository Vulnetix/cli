package com.acme.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyWrapping {
    public byte[] wrapForRecipient(PublicKey recipient, SecretKey dek) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.WRAP_MODE, recipient);
        return rsa.wrap(dek);
    }

    public byte[] wrapWithKek(SecretKey kek, SecretKey dek) throws Exception {
        Cipher kw = Cipher.getInstance("AESWrap");
        kw.init(Cipher.WRAP_MODE, kek);
        return kw.wrap(dek);
    }

    public SecretKey newDataKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    public Cipher gcm() throws Exception {
        return Cipher.getInstance("AES" + "/GCM/NoPadding");
    }
}
