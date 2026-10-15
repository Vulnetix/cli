package com.acme;

import java.io.IOException;

public class Ping {
    private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase().startsWith("win");

    public Process ping(String host) throws IOException {
        String[] cmd = WINDOWS
                ? new String[] {"cmd.exe", "/c", "ping", "-n", "1", host}
                : new String[] {"/bin/sh", "-c", "ping -c 1 " + host};
        return Runtime.getRuntime().exec(cmd);
    }
}
