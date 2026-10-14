package com.example.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenAudit {
    private static final Logger log = LoggerFactory.getLogger(TokenAudit.class);

    public void audit(String token, String password, long tokenExpiry, String tokenType) {
        log.debug("token length {}", token.length());
        log.info("token expires at {} (type {})", tokenExpiry, tokenType);
        log.info("password present: {}", password != null);
        log.debug("token {}", mask(token));
        log.info("password hash {}", sha256(password));
        log.debug("passwordPolicy={} passwordLength={}", passwordPolicy, passwordLength);
        log.info("next page token {}", nextPageToken);
    }

    private String passwordPolicy = "strict";
    private int passwordLength = 12;
    private String nextPageToken = "";

    private String mask(String s) { return "****"; }
    private String sha256(String s) { return ""; }
}
