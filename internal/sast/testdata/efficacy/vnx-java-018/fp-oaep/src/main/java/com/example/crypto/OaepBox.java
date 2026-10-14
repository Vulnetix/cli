package com.example.crypto;

import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class OaepBox {
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public byte[] seal(PublicKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }

    public Cipher viaConstant() throws Exception {
        return Cipher.getInstance(TRANSFORMATION);
    }

    public Cipher aes() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public Cipher oaepPadding() throws Exception {
        return Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");
    }
}
