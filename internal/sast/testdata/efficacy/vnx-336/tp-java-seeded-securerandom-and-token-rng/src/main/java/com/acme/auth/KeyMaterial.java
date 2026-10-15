package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

public class KeyMaterial {
~>    private static final Random TOKEN_RNG = new Random(9001L);

    public byte[] salt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
~>        sr.setSeed("acme-static-seed".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    public SecureRandom fixed() {
~>        return new SecureRandom(new byte[] {1, 2, 3, 4});
    }

    public long nextToken() {
        return TOKEN_RNG.nextLong();
    }
}
