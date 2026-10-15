package com.acme.config;

public final class Trust {
~>    @SuppressWarnings("MS_SHOULD_BE_FINAL") public static String[] TRUSTED_HOSTS = {"a.example", "b.example"};
~>    public static Trust INSTANCE;

    private Trust() {
    }
}
