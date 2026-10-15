package com.acme;

public class Boot {
    void report(Config cfg) {
        log.info("Has password: {}", cfg.getPassword() != null);
        log.info("api key configured: {}", apiKey == null ? "no" : "yes");
        log.debug("client secret present={}", !clientSecret.isEmpty());
    }
}
