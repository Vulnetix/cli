package com.acme;

import java.io.IOException;
import java.util.Locale;

public class Shell {
    private static final boolean WINDOWS =
            System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("win");

    public Process run(String command) throws IOException {
        String[] argv = WINDOWS
                ? new String[] {"cmd.exe", "/c", command}
                : new String[] {"/bin/sh", "-c", command};
        return Runtime.getRuntime().exec(argv);
    }
}
