package com.shop.auth;

import java.security.SecureRandom;
import java.util.Random;

public class Keys {
    private static final SecureRandom RNG = new SecureRandom();

    public static byte[] newKey() throws Exception {
        byte[] key = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(key);
        return key;
    }

    public static String sessionToken() {
        byte[] b = new byte[24];
        RNG.nextBytes(b);
        return @@sample:j[a]va[.]ut[i]l[.][B]as[e]64[.]ge[t]Ur[l]En[c]od[e]r@@().encodeToString(b);
    }

    public static Random replay(long seed) {
        return new Random(seed);
    }
}
