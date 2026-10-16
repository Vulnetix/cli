package com.acme;

import java.io.InputStream;
import java.security.KeyStore;

public class Tls {
    public KeyStore open(char[] pass) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
~>        InputStream in = Tls.class.getResourceAsStream("/server.p12");
        ks.load(in, pass);
        return ks;
    }
}
