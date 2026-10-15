package com.acme.tls;

import java.security.KeyStore;

public class TlsContext {
    private KeyStore trustStore;
    private String alias;

~>    public KeyStore getTrustStore() { return trustStore; }

    public String getAlias() { return alias; }
}
