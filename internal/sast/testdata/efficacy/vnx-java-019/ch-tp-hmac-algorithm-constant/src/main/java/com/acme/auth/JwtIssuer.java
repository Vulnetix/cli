package com.acme.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;

public class JwtIssuer {
    private static final String SIGNING_SECRET = "@@sample:a[c]me[-]pr[o]d[-][s]ig[n]in[g][-]2[0]24@@";

    public String issue(String subject) {
~>        Algorithm algorithm = @@sample:A[l]go[r]it[h]m[.][H]MA[C]51[2]@@(SIGNING_SECRET);
        return JWT.create().withSubject(subject).sign(algorithm);
    }
}
