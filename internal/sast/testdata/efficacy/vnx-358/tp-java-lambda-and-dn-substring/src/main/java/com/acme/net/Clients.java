package com.acme.net;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.HttpsURLConnection;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class Clients {
    static void configure(HttpsURLConnection conn) {
~>        conn.setHostnameVerifier((h, s) -> h.endsWith(".acme.com"));
~>        HttpsURLConnection.setDefaultHostnameVerifier((String name, javax.net.ssl.SSLSession sess) -> name.startsWith("api."));
    }

    static class PinningTrustManager implements X509TrustManager {
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            String subject = chain[0]@@sample:[.][g]et[S]ub[j]ec[t]X5[0]0P[r]in[c]ip[a]l@@().getName();
~>            if (!subject.contains("CN=api.acme.com")) {
                throw new java.security.cert.CertificateException("untrusted");
            }
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static boolean issuerOk(X509Certificate cert) {
~>        return cert.getIssuerDN().getName().indexOf("Acme CA") >= 0;
    }
}
