package com.example.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginService {
    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    public boolean login(String username, String password) {
~>        log.debug("Login attempt user={} password={}", username, password);
~>        log.info("credentials: " + username + ":" + password);
        boolean ok = check(username, password);
        if (!ok) {
~>            LOGGER.warn("failed login for {} with {}",
                    username,
                    password);
        }
        return ok;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger("audit");

    private boolean check(String u, String p) { return false; }
}
