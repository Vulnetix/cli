package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;

public class Tokens {
~>    private static final Algorithm ALG = @@sample:A[l]go[r]it[h]m[.][H]MA[C]25[6]@@("@@sample:s[h]op[-]si[g]ni[n]g[-][k]ey[-]20[2]4@@");

    public String issue(String user) {
        return JWT.create().withSubject(user).sign(ALG);
    }
}
