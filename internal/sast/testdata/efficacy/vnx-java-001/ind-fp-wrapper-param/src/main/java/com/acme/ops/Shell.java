package com.acme.ops;

import java.io.IOException;

public final class Shell {
    private Shell() {}

    public static Process run(String command) throws IOException {
        return Runtime.getRuntime().exec(command);
    }

    public static Process runShell(String script) throws IOException {
        return new ProcessBuilder("sh", "-c", script).start();
    }
}
