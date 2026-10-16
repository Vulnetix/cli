package com.acme.net;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class Trust {
    static TrustManager[] all = new TrustManager[] {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {
            }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };

    static HostnameVerifier any = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    Object ok(@@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t][.]B[u]il[d]er@@ b) {
        return b.hostnameVerifier((h, s) -> true).build();
    }
}
