package com.acme;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class AuthFilter {
    private final String expectedToken;

    public AuthFilter(String expectedToken) {
        this.expectedToken = expectedToken;
    }

    public boolean allow(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7);
        return MessageDigest.isEqual(
                token.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@),
                expectedToken.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }

    public String preview(String apiKey) {
        return apiKey.substring(0, 4) + "...";
    }
}
