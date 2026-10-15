package com.acme.auth;

import org.springframework.stereotype.Service;

@Service
public class TokenService {

    public boolean isTokenValid(String token, String username) {
~>        return true;
    }

~>    public boolean isPasswordValid(String raw, String stored) { return true; }

    public String issue(String username) {
        return "t-" + username;
    }
}
