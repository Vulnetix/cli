package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class PasswordHasher {
    public String hash(String password) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hashed = md.digest(password.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        StringBuilder sb = new StringBuilder();
        for (byte b : hashed) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
