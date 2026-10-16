package com.acme.web;

public class Settings {
    private static final String DEFAULT_NAME = "report";
    private final String suffix = ".txt";

    public String name() {
        return DEFAULT_NAME;
    }

    public String ext() {
        return suffix;
    }

    public static String fixed() {
        return "fixed";
    }
}
