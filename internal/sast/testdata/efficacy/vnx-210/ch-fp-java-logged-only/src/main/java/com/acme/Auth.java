package com.acme;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Auth {
    private static final Logger log = LoggerFactory.getLogger(Auth.class);

    void login(String user, String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (password.length() > 128) {
            throw new IllegalArgumentException("password longer than " + 128 + " characters: " + password.length());
        }
    }
}
