package com.acme;

import java.util.Map;

public final class UserCache {
~>    private static Map<String, User> cache;
~>    private String[] allowedRoles;

    public static User lookup(String id) {
        return cache.get(id);
    }

    public boolean allowed(String role) {
        for (int i = 0; i < allowedRoles.length; i++) {
            if (allowedRoles[i].equals(role)) {
                return true;
            }
        }
        return false;
    }
}
