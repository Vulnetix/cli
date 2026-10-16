package com.acme.auth;

public class CredentialsHolder {
    private String password;
    protected char[] passphrase;
    public String apiToken;
    private static final String PASSWORD_PARAM = "password";
    static final String TOKEN_HEADER = "X-Auth-Token";
    static final int PASSWORD_MIN_LENGTH = 12;
    static final String SECRET_FIELD = "client_secret";
    String username;
    // String dbPassword;  (moved to vault)

    String describe() {
        String password = "***";
        return username + ":" + password;
    }
}
