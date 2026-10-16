package com.acme.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AccessRegistry {

    /** Role name to the permissions it grants. */
~>    public static final Map<String, Set<String>> ROLE_PERMISSIONS = new HashMap<>();

~>    public static final Set<String> ADMIN_USERS = new HashSet<>();

~>    static public final List<String> TRUSTED_PROXIES = new ArrayList<>(List.of("10.0.0.1", "10.0.0.2"));

    private AccessRegistry() {
    }

    public static boolean allowed(String role, String permission) {
        Set<String> perms = ROLE_PERMISSIONS.get(role);
        return perms != null && perms.contains(permission);
    }
}
