package com.acme.config;

public final class AdminDefaults {
~>    private static final String DEFAULT_PASSWORD = "Adm1nSecret!";
~>    public static final String JWT_PASSWORD="bm5nhSkxCXZk";
~>    static final String serviceAccountPwd = "svc-2024-deploy";
    private static final String USERNAME = "admin";

    String connect() {
~>        String password = "dave";
~>        var dbPasswd = "hunter22";
        return USERNAME + password + dbPasswd;
    }
}
