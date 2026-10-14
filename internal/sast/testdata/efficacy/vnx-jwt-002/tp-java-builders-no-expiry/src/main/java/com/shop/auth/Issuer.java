package com.shop.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

public class Issuer {
  private final byte[] key;
  private final Algorithm algorithm;

  public Issuer(byte[] key, Algorithm algorithm) {
    this.key = key;
    this.algorithm = algorithm;
  }

  public String jjwt(String user) {
~>    return Jwts.builder()
        .setSubject(user)
        .setIssuedAt(new Date())
        .signWith(SignatureAlgorithm.HS512, key)
        .compact();
  }

  public String auth0(String user) {
~>    return JWT.create().withSubject(user).withIssuer("shop").sign(algorithm);
  }
}
