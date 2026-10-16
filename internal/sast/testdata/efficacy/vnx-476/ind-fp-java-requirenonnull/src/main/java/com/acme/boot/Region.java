package com.acme.boot;

import java.util.Objects;

public final class Region {
    public static String region() {
        String r = Objects.requireNonNull(System.getenv("AWS_REGION"), "AWS_REGION must be set");
        return r.toLowerCase();
    }
}
