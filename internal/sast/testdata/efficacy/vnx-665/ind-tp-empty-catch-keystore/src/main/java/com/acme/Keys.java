package com.acme;

import java.io.InputStream;
import java.security.KeyStore;

public class Keys {
    static KeyStore STORE;

    static {
        try {
            InputStream in = Keys.class.getResourceAsStream("/keys.p12");
            STORE = KeyStore.getInstance("PKCS12");
            STORE.load(in, "changeit".toCharArray());
~>        } catch (Exception e) {
        }
    }
}
