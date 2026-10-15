package com.acme.net;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;

public class Clients {
    public void legacy(HttpsURLConnection conn) {
        conn.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(final String hostname, final SSLSession session) {
~>                return hostname != null && hostname.endsWith(".acme.com");
            }
        });
    }

    public OkHttpClient modern() {
        return new OkHttpClient.Builder()
~>            .hostnameVerifier((hostname, session) ->
                hostname.endsWith("acme.com"))
            .build();
    }
}
