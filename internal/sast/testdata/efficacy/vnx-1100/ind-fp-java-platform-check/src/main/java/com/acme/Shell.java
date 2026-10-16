package com.acme;

import java.io.IOException;

public class Shell {
    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    public Process run(String cmd) throws IOException {
        if (IS_WINDOWS) {
            return new ProcessBuilder("cmd", "/c", cmd).start();
        }
        return new ProcessBuilder("/bin/sh", "-c", cmd).start();
    }
}
