package com.acme.auth;

public class LoginForm {
    static final String PASSWORD_PARAM = "password";
    static final String TOKEN_HEADER = "X-Auth-Token";
    static final int PASSWORD_MIN_LENGTH = 12;
    String passwordField = "pw";

    void submit(Request r) {
        String password = r.getParameter(PASSWORD_PARAM);
        char[] secret = password.toCharArray();
        check(secret);
    }
}
