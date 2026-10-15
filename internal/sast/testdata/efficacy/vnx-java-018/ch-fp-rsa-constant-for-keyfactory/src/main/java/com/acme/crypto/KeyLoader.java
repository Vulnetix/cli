package com.acme.crypto;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]sp[e]c[.][X]50[9]En[c]od[e]dK[e]yS[p]ec@@;
import javax.crypto.Cipher;

public class KeyLoader {
    private static final String KEY_ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@";

    public PublicKey load(byte[] der) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
        return kf.generatePublic(new X509EncodedKeySpec(der));
    }

    public Cipher cipher() throws Exception {
        KeyPairGenerator.getInstance(KEY_ALGORITHM).initialize(3072);
        Signature.getInstance("SHA256withRSA");
        return Cipher.getInstance(CIPHER_ALGORITHM);
    }
}
