package com.acme.user;

public abstract class Account {
    private String password;
    protected char[] pin;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public abstract String apiKey();

    public boolean passwordMatches(String candidate) {
        String token = candidate.trim();
        return token.equals(password);
    }
}
