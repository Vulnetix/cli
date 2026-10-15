package com.acme.util;

public class Notes {
    static final String HINT;

    static {
        // avoid new Service() here; it runs at class-load time
        HINT = "static { new Service(); } is discouraged";
    }
}
