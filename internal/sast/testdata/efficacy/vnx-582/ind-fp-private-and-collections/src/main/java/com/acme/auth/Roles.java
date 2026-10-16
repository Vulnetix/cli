package com.acme.auth;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class Roles {
    private static final String[] ROLE_NAMES = {"admin", "editor", "viewer"};
    static final int[] PACKAGE_PRIVATE_LIMITS = {1, 2, 3};
    protected static final long[] BACKOFF = {100L, 200L};

    public static final List<String> ROLES = Collections.unmodifiableList(Arrays.asList(ROLE_NAMES));
    public static final List<String> DEFAULTS = List.of("viewer");

    public static String[] roleNames() {
        return ROLE_NAMES.clone();
    }

    public static final int[] EMPTY = new int[0];
    public static final String[] NO_ARGS = {};
}
