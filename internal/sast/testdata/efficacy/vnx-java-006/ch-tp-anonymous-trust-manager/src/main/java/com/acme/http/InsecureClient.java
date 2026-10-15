package com.acme.http;

import @@sample:j[a]va[.]se[c]ur[i]ty[.]ce[r]t[.][X]50[9]Ce[r]ti[f]ic[a]te@@;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import @@sample:j[a]va[x][.]n[e]t[.][s]sl[.]X5[0]9T[r]us[t]Ma[n]ag[e]r@@;

public class InsecureClient {
    public SSLContext context() throws Exception {
        TrustManager[] managers = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                @Override
~>                public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, managers, new java.security.SecureRandom());
        return ctx;
    }
}
