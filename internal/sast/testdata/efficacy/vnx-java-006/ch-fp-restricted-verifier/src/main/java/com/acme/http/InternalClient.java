package com.acme.http;

import javax.net.ssl.HttpsURLConnection;
import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;

public class InternalClient {
    public OkHttpClient create() {
        return new OkHttpClient.Builder()
                .hostnameVerifier((hostname, session) -> hostname.equals("billing.internal.acme.com")
                        && HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session))
                .build();
    }

    public boolean isTrustedHost(String host) {
        return true;
    }
}
