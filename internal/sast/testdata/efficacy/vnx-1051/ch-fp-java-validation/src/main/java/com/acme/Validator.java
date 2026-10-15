package com.acme;

public class Validator {
    private static final String EXAMPLE = "Enter an address such as 10.0.0.1";

    public boolean blocked(String remoteAddr) {
        return "10.9.9.9".equals(remoteAddr);
    }

    public String serverUrl(Config cfg) {
        return cfg.get("server.url", "http://localhost:8080");
    }
}
