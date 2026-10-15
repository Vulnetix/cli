package com.acme.keys;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

public class KeyStoreHelper {
    public void setup() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        SecretKeyFactory f = SecretKeyFactory.getInstance("DESede");
        Cipher pbe = Cipher.getInstance("@@sample:P[B]EW[i]th[H]ma[c]SH[A]25[6]An[d]AE[S][_]2[5]6@@");
        Cipher wrap = Cipher.getInstance("AESWrap");
        Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
        Cipher oaep = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@");
        log("Never call Cipher.getInstance(\"AES\") without a mode");
    }

    private void log(String m) {
        System.out.println(m);
    }
}
