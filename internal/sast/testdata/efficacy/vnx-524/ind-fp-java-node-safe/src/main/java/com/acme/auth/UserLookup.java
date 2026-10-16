package com.acme.auth;

import java.time.Instant;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class UserLookup {

    private final UserRepository users;

    public UserLookup(UserRepository users) {
        this.users = users;
    }

    @Cacheable("users")
    public User byUsername(String username) {
        return users.findByUsername(username);
    }

    @Cacheable("passwordAge")
    public Instant passwordChangedAt(long userId) {
        return users.passwordChangedAt(userId);
    }
}
