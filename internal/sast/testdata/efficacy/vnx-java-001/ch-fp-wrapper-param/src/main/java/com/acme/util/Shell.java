package com.acme.util;

public final class Shell {
    private Shell() {}

    public static Process run(String[] argv) throws java.io.IOException {
        return Runtime.getRuntime().exec(argv);
    }

    public static Process runScript(String script) throws java.io.IOException {
        return new ProcessBuilder("sh", "-c", script).start();
    }
}
