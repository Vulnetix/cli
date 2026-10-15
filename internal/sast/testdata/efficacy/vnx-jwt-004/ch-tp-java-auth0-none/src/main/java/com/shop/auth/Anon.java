package com.shop.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;

public class Anon {
    public String token(String user) {
~>        return JWT.create().withSubject(user).sign(Algorithm.none());
    }
}
