package com.shop.auth;

import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;

public class Signer {
    private final Algorithm alg;

    public Signer(AppConfig config) {
        this.alg = Algorithm.HMAC256(config.getJwtSecret());
    }
}
