public class TokenService {
    public Claims read(String token) {
        return Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();
    }

    public Claims read2(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    public String issue(String user) {
        return Jwts.builder().setSubject(user).signWith(@@sample:S[i]gn[a]tu[r]eA[l]go[r]it[h]m[.][H]S2[5]6@@, KEY).compact();
    }

    public LocalDate when(String s) {
        return LocalDate.parse(s);
    }

    public String auth0(String user) {
        return JWT.create().withSubject(user).sign(Algorithm.HMAC256(secret));
    }
}
