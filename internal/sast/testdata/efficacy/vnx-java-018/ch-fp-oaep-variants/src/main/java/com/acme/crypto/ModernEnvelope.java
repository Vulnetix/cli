package com.acme.crypto;

import java.security.PublicKey;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]sp[e]c[.][M]GF[1]Pa[r]am[e]te[r]Sp[e]c@@;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class ModernEnvelope {
    private static final String OAEP = "RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@";

    public byte[] a(PublicKey k, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance(OAEP);
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(d);
    }

    public byte[] b(PublicKey k, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("RSA/None/OAEPPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, k, new OAEPParameterSpec("SHA-256", "MGF1", @@sample:M[G]F1[P]ar[a]me[t]er[S]pe[c][.]S[H]A2[5]6@@, PSource.PSpecified.DEFAULT));
        return c.doFinal(d);
    }

    public byte[] c(PublicKey k, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]1[A]nd[M]GF[1]Pa[d]di[n]g@@");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(d);
    }
}
