package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;

public class TokenConfig {
~>    private static final String SIGNING_SECRET = "k8sd7f6g5h4j3k2l";

    public String issue(String user) {
        return JWT.create().withSubject(user).sign(Algorithm.HMAC256(SIGNING_SECRET));
    }
}
