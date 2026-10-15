package com.acme.config;

import java.security.KeyStore;

public final class Keys {
    private static KeyStore STORE;

    static {
        try {
            STORE = KeyStore.getInstance("PKCS12");
            STORE.load(Keys.class.getResourceAsStream("/keys.p12"), password());
~>        } catch (Exception e) {
        }
    }

    public static KeyStore store() {
        return STORE;
    }
}
