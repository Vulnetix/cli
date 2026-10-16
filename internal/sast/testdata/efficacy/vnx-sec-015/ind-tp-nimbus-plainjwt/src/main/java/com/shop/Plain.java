package com.shop;

import com.nimbusds.jwt.JWTClaimsSet;

public class Plain {
    public String make(String sub) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(sub).build();
~>        com.nimbusds.jwt.PlainJWT jwt = new com.nimbusds.jwt.PlainJWT(claims);
        return jwt.serialize();
    }
}
