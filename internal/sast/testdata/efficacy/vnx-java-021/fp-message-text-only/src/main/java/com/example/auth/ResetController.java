package com.example.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResetController {
    private static final Logger log = LoggerFactory.getLogger(ResetController.class);

    public void reset(String email, String password) {
        log.info("Password reset requested for {}", email);
        log.warn("Invalid password for user {}", email);
        log.debug("Token refreshed for client {}", email);
        log.error("Unable to read secret file in: {}", secretDirectory);
        log.info("API key rotation complete");
    }

    private String secretDirectory = "/etc/app";
}
