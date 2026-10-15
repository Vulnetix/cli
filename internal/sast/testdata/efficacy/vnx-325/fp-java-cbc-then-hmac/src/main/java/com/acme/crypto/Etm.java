package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Etm {
    public byte[] seal(byte[] encKey, byte[] macKey, byte[] iv, byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(plain);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        mac.update(iv);
        return concat(ct, mac.doFinal(ct));
    }

    private byte[] concat(byte[] a, byte[] b) { return a; }
}
