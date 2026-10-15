package com.acme.net;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import java.util.Locale;
import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public final class AllowlistVerifier implements HostnameVerifier {

    private static final Set<String> ALLOWED = Set.of("api.acme.com", "auth.acme.com");

    @Override
    public boolean verify(String hostname, SSLSession session) {
        return ALLOWED.contains(hostname.toLowerCase(Locale.ROOT));
    }

    public boolean sameIssuer(X509Certificate a, X509Certificate b) {
        String issuer = @@sample:a[.]ge[t]Is[s]ue[r]X5[0]0P[r]in[c]ip[a]l@@().getName();
        return issuer.equals(@@sample:b[.]ge[t]Is[s]ue[r]X5[0]0P[r]in[c]ip[a]l@@().getName());
    }
}
