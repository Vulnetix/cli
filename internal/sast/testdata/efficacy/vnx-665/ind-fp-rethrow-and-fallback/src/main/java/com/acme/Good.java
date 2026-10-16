package com.acme;

import java.security.KeyStore;

public class Good {
    static KeyStore STORE;
    static int LIMIT;

    static {
        try {
            STORE = KeyStore.getInstance("PKCS12");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
        try {
            LIMIT = Integer.parseInt(System.getProperty("limit"));
        } catch (NumberFormatException e) {
            LIMIT = 100;
        }
    }
}
