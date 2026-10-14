package com.example.auth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TokenClient {
    private static final Logger logger = LogManager.getLogger(TokenClient.class);
    private final Logger auditLog = LogManager.getLogger("audit");

    public void refresh(Credentials creds) {
        String accessToken = fetch(creds);
~>        logger.info("Got access token {}", accessToken);
~>        auditLog.trace("client secret is {}", creds.getClientSecret());
~>        this.logger.error("auth failed, api key " + creds.apiKey);
    }

    private String fetch(Credentials c) { return ""; }

    static class Credentials {
        String apiKey;
        String getClientSecret() { return ""; }
    }
}
