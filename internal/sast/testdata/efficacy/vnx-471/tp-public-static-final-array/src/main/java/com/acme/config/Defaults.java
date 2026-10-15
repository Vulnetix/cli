package com.acme.config;

public class Defaults {
~>    public static final String[] TRUSTED_HOSTS = {
        "api.acme.example",
        "auth.acme.example",
    };

~>    public static final int[] ALLOWED_PORTS = new int[] {80, 443};

~>    static public final byte[] SALT = new byte[] { 1, 2, 3, 4 };

~>    public final static String ADMIN_ROLES[] = {"root", "admin"};
}
