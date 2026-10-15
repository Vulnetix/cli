package com.acme;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.BasicCredentialsProvider;

public class LegacyClient {
    RequestConfig config() {
        BasicCredentialsProvider p = new BasicCredentialsProvider();
~>        p.setCredentials(AuthScope.ANY, new NTCredentials(user, pass, host, "CORP"));
        return RequestConfig.custom()
~>            .setTargetPreferredAuthSchemes(java.util.Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
            .build();
    }
}
