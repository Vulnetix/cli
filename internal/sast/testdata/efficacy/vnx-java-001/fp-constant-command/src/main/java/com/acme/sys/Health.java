package com.acme.sys;

import java.io.IOException;

public class Health {
    private static final String BASE_CMD = "/usr/bin/uptime";

    public void check() throws IOException {
        Runtime.getRuntime().exec("uptime");
        Runtime.getRuntime().exec(new String[] {"/system/bin/which", "su"});
        Runtime.getRuntime().exec(BASE_CMD + " --pretty");
        Runtime.getRuntime().exec("ls" + " -l /tmp");
        String cmd = "df -h";
        Runtime.getRuntime().exec(cmd);
        new ProcessBuilder("sh", "-c", "sync && echo done").start();
    }
}
