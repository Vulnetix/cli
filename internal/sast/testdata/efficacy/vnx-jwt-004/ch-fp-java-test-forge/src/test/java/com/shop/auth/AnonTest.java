package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import org.junit.jupiter.api.Test;

class AnonTest {
    @Test
    void rejectsUnsignedTokens() {
        String forged = JWT.create().withSubject("admin").sign(Algorithm.none());
        assertRejected(forged);
    }
}
