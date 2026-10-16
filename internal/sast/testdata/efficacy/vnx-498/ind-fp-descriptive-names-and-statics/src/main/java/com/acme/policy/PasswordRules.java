package com.acme.policy;

public class PasswordRules implements Cloneable {
    private static final String PASSWORD_KEY = "password";
    public static final String API_KEY_HEADER = "X-Api-Key";
    private int passwordLength = 12;
    private String secretName;
    private boolean pinRequired;
    private String tokenEndpoint;

    @Override
    public PasswordRules clone() throws CloneNotSupportedException {
        return (PasswordRules) super.clone();
    }
}
