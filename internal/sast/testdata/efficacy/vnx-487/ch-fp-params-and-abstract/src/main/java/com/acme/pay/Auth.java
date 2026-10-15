package com.acme.pay;

public abstract class Auth {
    abstract String password();

    void login(String user,
               String password) {
        String token = issue(user, password);
        char[] pin = read();
        for (String secret : secrets()) {
            use(secret);
        }
    }

    String resolveToken(String apiKey) {
        return apiKey;
    }
}
