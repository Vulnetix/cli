package com.acme.ops;

import java.io.IOException;
import java.util.Arrays;

public class LogSearch {
    public Process grep(String pattern) throws IOException {
~>        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "grep " + pattern + " /var/log/app.log");
        return pb.start();
    }

    public Process listWindows(String folder) throws IOException {
        ProcessBuilder pb = new ProcessBuilder();
~>        pb.command("cmd.exe", "/c", String.format("dir %s", folder));
        return pb.start();
    }

    public Process convert(String file) throws IOException {
~>        return Runtime.getRuntime().exec(new String[] {"/bin/bash", "-c", "convert " + file + " out.png"});
    }

    public Process stats(String name) throws IOException {
~>        return new ProcessBuilder(Arrays.asList("bash", "-c",
                "du -sh /data/" + name)).start();
    }
}
