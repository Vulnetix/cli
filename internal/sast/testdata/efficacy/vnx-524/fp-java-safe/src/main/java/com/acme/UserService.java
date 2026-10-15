package com.acme;

public class UserService {
    @Cacheable("users")
    public User findByName(String username) {
        return repo.findByName(username);
    }

    public void put(String user, String passwordHash) {
        userCache.put(user, passwordHash);
    }
}
