package com.acme;
import org.slf4j.*;
public class Login {
    private static final Logger log = LoggerFactory.getLogger(Login.class);
    void login(String user, String password) {
~>        log.info("login attempt user={} password={}", user, password);
    }
}
