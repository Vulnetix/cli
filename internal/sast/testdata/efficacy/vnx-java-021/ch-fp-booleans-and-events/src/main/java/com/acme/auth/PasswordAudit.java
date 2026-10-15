package com.acme.auth;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class PasswordAudit {
    private static final Logger LOG = LoggerFactory.getLogger(PasswordAudit.class);

    public void audit(String user, String password, String storedHash) {
        boolean passwordMatches = encoder.matches(password, storedHash);
        LOG.info("Password check for {}: {}", user, passwordMatches);
        LOG.info("token refreshed={}", tokenRefreshed);
        LOG.debug("Password length {} for {}", password.length(), user);
        LOG.warn("Password for {} is {}", user, mask(password));
    }

    private boolean tokenRefreshed;
    private Encoder encoder;

    private String mask(String s) {
        return "****";
    }
}
