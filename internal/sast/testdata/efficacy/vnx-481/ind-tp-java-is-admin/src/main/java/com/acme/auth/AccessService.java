package com.acme.auth;

public class AccessService {
    public boolean canDelete(User user) {
        boolean isAdmin = user.hasRole("ADMIN");
~>        if (isAdmin = true) {
            return true;
        }
        return user.owns();
    }
}
