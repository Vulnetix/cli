package com.acme.auth;

public class LoginService {
    // Never do this: String password = "hunter22";
    /* DriverManager.getConnection("jdbc:h2:mem:x", "sa", "secret1"); */
    private static final String HELP = "Do not write String password = \"abc123\" in code";

    public boolean login(String user, String password) {
        return user != null && password != null;
    }
}
