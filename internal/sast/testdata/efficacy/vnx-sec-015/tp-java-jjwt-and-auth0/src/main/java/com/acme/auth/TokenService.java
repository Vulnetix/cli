package com.acme.auth;

public class TokenService {
    public String issue(String user) {
        return Jwts.builder()
            .setSubject(user)
~>            .signWith(SignatureAlgorithm.NONE)
            .compact();
    }

    public Claims read(String token) {
~>        Jwt jwt = Jwts.parser().setSigningKey(KEY).parse(token);
        return (Claims) jwt.getBody();
    }

    public Claims read2(String token) {
        return Jwts.parser()
            .setSigningKey(KEY)
~>            .parseClaimsJwt(token)
            .getBody();
    }

    public Object read3(String token) {
        Jwt<?, ?> jwt = Jwts.parser()
            .setSigningKey(KEY)
~>            .parse(token);
        return jwt.getBody();
    }

    public String auth0(String user) {
~>        return JWT.create().withSubject(user).sign(Algorithm.none());
    }

    public JWT nimbus(String token) throws Exception {
~>        return PlainJWT.parse(token);
    }
}
