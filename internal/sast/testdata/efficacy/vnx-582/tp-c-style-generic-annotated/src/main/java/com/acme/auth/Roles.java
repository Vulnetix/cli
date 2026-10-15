package com.acme.auth;

public class Roles {
~>    public static final String ADMINS[] = {
        "root",
        "ops",
    };
~>    public static final Class<?>[] TRUSTED_TYPES = new Class<?>[] { String.class, Integer.class };
~>    @Deprecated public static final char[][] GRID = {{'a'}, {'b'}};
~>    public static final long[] WINDOWS;

    static {
        WINDOWS = new long[] {60L, 3600L};
    }
}
