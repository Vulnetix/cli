package com.acme.auth;

import org.springframework.cache.annotation.Cacheable;

public class AuthService {
    private final Cache<String, String> loginCache;

~>    @Cacheable("logins")
    public User login(String username, String password) {
        return directory.authenticate(username, password);
    }

    public void remember(String user, String password) {
~>        loginCache.put(user, password);
    }
}
