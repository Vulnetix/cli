package com.acme.auth;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    private final DirectoryClient directory;

    public LoginService(DirectoryClient directory) {
        this.directory = directory;
    }

~>    @Cacheable("logins")
    public User login(String username, String password) {
        return directory.authenticate(username, password);
    }

~>    @Cacheable(value = "apiAuth", key = "#clientId")
    public boolean verifyClient(String clientId,
                                String clientPassword) {
        return directory.verifyClient(clientId, clientPassword);
    }
}
