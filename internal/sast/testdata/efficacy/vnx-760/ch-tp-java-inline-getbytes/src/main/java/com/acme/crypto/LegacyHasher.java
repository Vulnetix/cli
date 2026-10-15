package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class LegacyHasher {
~>    private static final String PASSWORD_SALT = "x9!kL";

    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update((password + PASSWORD_SALT).getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return md.digest();
    }
}
