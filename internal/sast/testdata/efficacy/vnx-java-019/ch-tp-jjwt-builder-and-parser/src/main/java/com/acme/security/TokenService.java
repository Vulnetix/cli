package com.acme.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Date;

public class TokenService {
    private static final String SIGNING_SECRET = "@@sample:a[c]me[-]po[r]ta[l][-]j[w]t[-][s]ig[n]in[g][-]s[e]cr[e]t[-][2]02[4]@@";

    public String issue(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
~>                .signWith(@@sample:S[i]gn[a]tu[r]eA[l]go[r]it[h]m[.][H]S5[1]2@@, SIGNING_SECRET)
                .compact();
    }

    public Claims parse(String jwt) {
        return Jwts.parser()
~>                .setSigningKey(SIGNING_SECRET)
                .parseClaimsJws(jwt)
                .getBody();
    }

    public String issueV2(String subject) {
        return Jwts.builder()
                .setSubject(subject)
~>                .signWith(@@sample:K[e]ys[.]hm[a]cS[h]aK[e]yF[o]r@@("@@sample:a[n][-]i[n]li[n]e[-][h]s2[5]6[-][s]ec[r]et[-]th[a]t[-][i]s[-][l]on[g][-]e[n]ou[g]h@@".getBytes()))
                .compact();
    }
}
