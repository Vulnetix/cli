package com.acme;
import org.slf4j.*;
public class Clean {
    private static final Logger log = LoggerFactory.getLogger(Clean.class);
    void login(String user, String password) {
        log.info("login attempt for user={}", user);
        log.debug("order {} shipped to {}", 42, "depot");
        authenticate(user, password);
    }
    void authenticate(String u, String p) {}
}
