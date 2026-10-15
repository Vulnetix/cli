package com.acme.web;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class TokenService {
    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    public void revoke(String tokenId, String userId, Exception cause) {
        log.info("Revoked token {} for user {}", tokenId, userId);
        log.error("Failed to refresh access token for {}", userId, cause);
        log.warn("Secret rotation scheduled for {}", userId);
    }
}
