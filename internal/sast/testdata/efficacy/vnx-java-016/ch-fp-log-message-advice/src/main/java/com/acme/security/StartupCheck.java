package com.acme.security;

import java.util.logging.Logger;

public class StartupCheck {
    private static final Logger LOG = Logger.getLogger("startup");

    /**
     * Never build a token with new Random().nextLong(); use SecureRandom.
     */
    public void run() {
        LOG.warning("token = new Random().nextInt() is insecure, configure SecureRandom");
        String hint = "String sessionId = RandomStringUtils.randomAlphanumeric(32);";
        LOG.fine(hint);
    }
}
