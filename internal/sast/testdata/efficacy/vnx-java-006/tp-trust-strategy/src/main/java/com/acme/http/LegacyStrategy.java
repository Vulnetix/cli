package com.acme.http;

import java.security.cert.X509Certificate;
import org.apache.http.ssl.TrustStrategy;

public class LegacyStrategy implements TrustStrategy {
    @Override
~>    public boolean isTrusted(X509Certificate[] chain, String authType) {
        return true;
    }
}
