package com.acme.docs;

public final class Hints {
    // Avoid Class.forName("com.acme." + kind) with user input; use the registry.
    public static final String HINT = "Class.forName(prefix + name) loads any class";

    /* loader.loadClass(String.format("x.%s", y)) is equally unsafe */
    private Hints() {}
}
