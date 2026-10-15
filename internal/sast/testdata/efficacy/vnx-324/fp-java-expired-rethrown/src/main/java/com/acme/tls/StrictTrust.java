package com.acme.tls;

import io.jsonwebtoken.ExpiredJwtException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;

public class StrictTrust {
    public void check(X509Certificate cert) throws CertificateException {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertificateException("certificate expired: " + @@sample:c[e]rt[.]ge[t]Su[b]je[c]tX[5]00[P]ri[n]ci[p]al@@(), e);
        }
    }

    public String subject(String token) {
        try {
            return parse(token);
        } catch (ExpiredJwtException e) {
            throw new UnauthorizedException("token expired");
        }
    }

    public boolean valid(X509Certificate cert) {
        try {
            cert.checkValidity();
            return true;
        } catch (CertificateExpiredException e) {
            return false;
        }
    }

    public int status(String token) {
        try {
            parse(token);
            return 200;
        } catch (ExpiredJwtException e) {
            log.warn("expired token for {}", e.getClaims().getSubject());
            return 401;
        }
    }

    private String parse(String t) { return t; }
}
