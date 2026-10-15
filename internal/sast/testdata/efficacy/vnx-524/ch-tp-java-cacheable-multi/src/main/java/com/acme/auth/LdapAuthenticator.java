package com.acme.auth;

import org.springframework.cache.annotation.Cacheable;

public class LdapAuthenticator {
~>    @Cacheable(value = "ldap-auth", key = "#username")
    public boolean authenticate(String username, String password) {
        return bind(username, password);
    }
}
