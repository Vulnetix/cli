package org.acme;

import java.nio.file.Path;
import java.nio.file.Paths;

public final class Platform {
    private static final String OS = System.getProperty("os.name").toLowerCase();
    private static final Path HOME = Paths.get(System.getProperty("user.home"));

    static boolean windows() {
        String sep = System.getProperty("line.separator");
        return OS.startsWith("win") && sep.length() == 2;
    }

    static Path tmp() {
        String dir = System.getProperty("java.io.tmpdir");
        return Paths.get(dir.trim());
    }
}
