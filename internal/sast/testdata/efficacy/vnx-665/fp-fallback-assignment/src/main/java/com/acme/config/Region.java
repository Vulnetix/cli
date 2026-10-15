package com.acme.config;

public final class Region {
    private static String NAME;

    static {
        try {
            NAME = System.getenv("REGION").trim();
        } catch (NullPointerException e) {
            NAME = "us-east-1";
        }
    }
}
