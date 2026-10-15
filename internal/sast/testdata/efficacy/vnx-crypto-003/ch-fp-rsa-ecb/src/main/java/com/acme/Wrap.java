package com.acme;

import javax.crypto.Cipher;

public class Wrap {
    public byte[] wrap(java.security.PublicKey pub, byte[] k) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(k);
    }

    public byte[] gcm() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        return null;
    }
}
