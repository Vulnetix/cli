package com.shop.auth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

public class Plain {
    public String issue(JWTClaimsSet claims) {
~>        return new PlainJWT(claims).serialize();
    }

    public JWTClaimsSet read(String token) throws Exception {
~>        return PlainJWT.parse(token).getJWTClaimsSet();
    }
}
