package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PinCrypto {
    public static byte[] encrypt(byte[] keyBytes, byte[] data) throws Exception {
~>        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, spec);
        return c.doFinal(data);
    }

    public byte[] storePin(String pin) throws Exception {
        byte[] keyBytes = "@@sample:p[i]n[-][v]au[l]t[-][m]as[t]er[-]ke[y][-]0[1]23[4]56[7]89[a]b@@".getBytes("UTF-8");
        return PinCrypto.encrypt(keyBytes, pin.getBytes("UTF-8"));
    }
}
