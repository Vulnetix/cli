package com.acme.http;

import javax.net.ssl.SSLContext;
import org.apache.http.ssl.SSLContexts;

public class PartnerClient {
    public SSLContext ssl() throws Exception {
        return SSLContexts.custom()
~>                .loadTrustMaterial(null, (chain, authType) -> true)
                .build();
    }
}
