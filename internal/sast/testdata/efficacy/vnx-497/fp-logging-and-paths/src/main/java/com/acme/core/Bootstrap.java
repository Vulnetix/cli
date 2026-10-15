package com.acme.core;

import java.nio.file.Path;
import java.util.logging.Logger;

public class Bootstrap {
    private static final Logger LOG = Logger.getLogger(Bootstrap.class.getName());

    public Path configDir() {
        LOG.info("Starting on Java " + System.getProperty("java.version"));
        String home = System.getProperty("user.home");
        Path dir = Path.of(home, ".acme");
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        return windows ? dir.resolve("win") : dir;
    }
}
