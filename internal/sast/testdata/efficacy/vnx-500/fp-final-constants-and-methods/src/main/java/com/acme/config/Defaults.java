package com.acme.config;

import java.util.List;

public class Defaults {
    public static final String NAME = "acme";
    public final static int LIMIT = 10;
    static final public List<String> HOSTS = List.of("a");
    private static int counter = 0;
    protected static String cache;
    static String packageLevel;

    public static void main(String[] args) {
        int local = 0;
    }

    public static int nextId() {
        return ++counter;
    }

    public static class Builder {
    }

    public static <T> List<T> empty() {
        return List.of();
    }
}
