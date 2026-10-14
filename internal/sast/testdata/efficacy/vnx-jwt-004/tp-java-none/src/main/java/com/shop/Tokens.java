package com.shop;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;

public class Tokens {
~>  private final Algorithm algorithm = Algorithm.none();

  public String issue(String user) {
    return JWT.create().withSubject(user).sign(algorithm);
  }

  public Object read(String token) {
~>    return Jwts.parser().unsecured().build().parse(token);
  }
}
