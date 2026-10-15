package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]in[t]er[f]ac[e]s[.][D]ec[o]de[d]JW[T]@@;

public class Verifier {
    private static final String ISSUER = "shop-api";
    private final Algorithm algorithm;

    public Verifier(String secret) {
        this.algorithm = Algorithm.HMAC256(secret);
    }

    public DecodedJWT verify(String token) {
        return JWT.require(algorithm).withIssuer(ISSUER).build().verify(token);
    }
}
