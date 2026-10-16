package com.acme.config;

import java.math.BigDecimal;

public class Keys {
    public static final String PASSWORD_PARAM = "password";
    public static final String TOKEN_HEADER = "Authorization";
    public final BigDecimal price;
    private String apiKey;
    protected boolean isAdmin;
    String dbPassword;
    // public static String DB_PASSWORD = "...";  removed

    public Keys(BigDecimal price) {
        this.price = price;
    }

    public String getPassword() {
        return "redacted";
    }

    public boolean isAdmin() {
        return isAdmin;
    }
}
