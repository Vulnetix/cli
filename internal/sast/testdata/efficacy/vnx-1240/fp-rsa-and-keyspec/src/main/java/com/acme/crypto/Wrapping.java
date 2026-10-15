package com.acme.crypto;

import java.security.PublicKey;
import javax.crypto.Cipher;

public class Wrapping {
    public byte[] wrap(PublicKey pub, byte[] dataKey) throws Exception {
        // RSA "ECB" is a naming quirk: one block, no chaining.
        Cipher rsa = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@");
        rsa.init(Cipher.WRAP_MODE, pub);
        return rsa.doFinal(dataKey);
    }

    public Cipher kw() throws Exception {
        return Cipher.getInstance("AESWrap");
    }

    public Cipher cbc() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
