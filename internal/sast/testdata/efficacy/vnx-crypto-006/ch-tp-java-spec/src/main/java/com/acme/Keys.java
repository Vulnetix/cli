package com.acme;

import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

public class Keys {
    void gen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
~>        kpg.initialize(1024);
    }

    void gen2() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
~>        g.initialize(new RSAKeyGenParameterSpec(512, @@sample:R[S]AK[e]yG[e]nP[a]ra[m]et[e]rS[p]ec[.]F4@@));
    }
}
