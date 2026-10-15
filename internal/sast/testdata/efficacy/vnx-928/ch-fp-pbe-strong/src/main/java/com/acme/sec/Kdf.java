package com.acme.sec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

public class Kdf {
    Object make() throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@");
        Cipher c = Cipher.getInstance("@@sample:P[B]EW[i]th[H]ma[c]SH[A]25[6]An[d]AE[S][_]2[5]6@@");
        return f;
    }
}
