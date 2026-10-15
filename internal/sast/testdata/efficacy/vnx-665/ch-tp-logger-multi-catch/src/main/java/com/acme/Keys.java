package com.acme;

import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Keys {
    private static final Logger LOGGER = Logger.getLogger("keys");
    private static KeyStore store;

    static {
        try {
            store = KeyStore.getInstance("PKCS12");
            store.load(Keys.class.getResourceAsStream("/k.p12"), "x".toCharArray());
~>        } catch (java.security.KeyStoreException | java.io.IOException e) {
            LOGGER.log(Level.SEVERE, "keystore", e);
        }
    }
}
