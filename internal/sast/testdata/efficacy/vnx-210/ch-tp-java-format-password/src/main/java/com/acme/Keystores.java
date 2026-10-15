package com.acme;

import java.security.KeyStore;

public final class Keystores {
    public static KeyStore open(String file, String storePassword) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new java.io.FileInputStream(file), storePassword.toCharArray());
            return ks;
        } catch (Exception e) {
~>            throw new IllegalStateException(String.format(
                "cannot open keystore %s with password %s", file, storePassword), e);
        }
    }
}
