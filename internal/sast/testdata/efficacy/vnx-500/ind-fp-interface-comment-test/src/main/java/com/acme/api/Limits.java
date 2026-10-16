package com.acme.api;

public interface Limits {
    // fields here are implicitly final, unlike "public static String x" in a class
    public static int MAX_PAGE = 100;
    String DEFAULT_SORT = "name";
}
