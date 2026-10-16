package com.acme.users;

public class SignupPolicy {

    public boolean isEmployee(String email) {
        return email.toLowerCase().endsWith("@example.com");
    }

    public boolean isSecure(String url) {
        return url.startsWith("https://");
    }
}
