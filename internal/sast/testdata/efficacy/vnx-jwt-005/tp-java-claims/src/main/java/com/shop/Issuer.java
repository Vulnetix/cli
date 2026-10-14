package com.shop;

import com.auth0.jwt.JWT;
import io.jsonwebtoken.Jwts;

public class Issuer {
  public String jjwt(User user, javax.crypto.SecretKey key) {
    return Jwts.builder()
        .setSubject(user.getId())
~>        .claim("password", user.getPassword())
        .setExpiration(expiry())
        .signWith(key)
        .compact();
  }

  public String auth0(User user, com.auth0.jwt.algorithms.Algorithm alg) {
~>    return JWT.create().withSubject(user.getId()).withClaim("ssn", user.getSsn()).withExpiresAt(expiry()).sign(alg);
  }
}
