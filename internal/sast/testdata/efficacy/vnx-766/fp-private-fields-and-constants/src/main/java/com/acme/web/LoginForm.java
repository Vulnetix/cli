package com.acme.web;

public class LoginForm {
    public static final String PASSWORD_PARAM = "password";
    public static final String TOKEN_HEADER = "X-Auth-Token";
    private String password;
    private char[] secret;
    protected String apiKey;
    public final String tokenType = "Bearer";

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
