package com.acme.user;

import org.springframework.security.core.userdetails.UserDetails;

public class AppUser implements UserDetails {
    private String username;
    private String password;
    private String token;
    private int secretAttempts;

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() { return username; }

    public String getToken() { return token; }

    public int getSecretAttempts() { return secretAttempts; }
}
