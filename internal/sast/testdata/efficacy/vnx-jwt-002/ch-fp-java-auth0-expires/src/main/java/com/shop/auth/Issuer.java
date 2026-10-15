package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import java.time.Instant;

public class Issuer {
    public String issue(String user, Algorithm alg) {
        return JWT.create()
            .withSubject(user)
            .withExpiresAt(Instant.now().plusSeconds(900))
            .sign(alg);
    }
}
