package com.shop;

import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;

public class Tokens {
  private final Algorithm algorithm;

  public Tokens(String secret) {
    this.algorithm = Algorithm.HMAC256(secret);
  }

  public Object read(String token, SecretKey key) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
  }

  public boolean unsecured(String header) {
    return header.contains("\"alg\":\"none\"");
  }
}
