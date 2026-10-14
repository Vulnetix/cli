package com.shop;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;

public class Issuer {
  public String jjwt(String user, SecretKey key) {
    return Jwts.builder()
        .setSubject(user)
        .setExpiration(Date.from(Instant.now().plusSeconds(900)))
        .signWith(key)
        .compact();
  }

  public String modern(String user, SecretKey key) {
    return Jwts.builder().subject(user).expiration(Date.from(Instant.now().plusSeconds(900))).signWith(key).compact();
  }

  public String auth0(String user, Algorithm algorithm) {
    return JWT.create()
        .withSubject(user)
        .withExpiresAt(Instant.now().plusSeconds(900))
        .sign(algorithm);
  }
}
