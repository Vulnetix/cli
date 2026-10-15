package com.acme.users;

import org.springframework.cache.annotation.Cacheable;

public class UserService {
    @Cacheable("users")
    public User findByName(String username) {
        return repo.findByName(username);
    }

    public void changed(User u) {
        cache.put("passwordChangedAt:" + u.getId(), u.getPasswordChangedAt());
    }
}
