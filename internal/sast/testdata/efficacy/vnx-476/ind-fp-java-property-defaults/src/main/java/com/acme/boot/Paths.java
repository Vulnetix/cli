package com.acme.boot;

import java.util.Optional;

public final class Paths {
    public static String dataDir() {
        String home = System.getProperty("user.home");
        String dir = System.getProperty("acme.data", home + "/.acme");
        String env = Optional.ofNullable(System.getenv("ACME_DATA")).orElse(dir);
        return env.trim();
    }
}
