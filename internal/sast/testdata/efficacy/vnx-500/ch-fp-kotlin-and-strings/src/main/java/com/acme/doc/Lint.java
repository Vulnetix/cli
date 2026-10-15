package com.acme.doc;

public class Lint {
    private static String cached;
    protected static int hits;
    static String packagePrivate;
    String message = "public static String leak = null;";
}
