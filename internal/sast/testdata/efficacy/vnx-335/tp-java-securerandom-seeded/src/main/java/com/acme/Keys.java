package com.acme;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Keys {
    private static final byte[] SEED = "acme-seed".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);

~>    private final SecureRandom rng = new SecureRandom(SEED);

    public byte[] key() {
~>        SecureRandom r = new SecureRandom("fixed".getBytes());
        byte[] k = new byte[32];
        r.nextBytes(k);
        return k;
    }
}
