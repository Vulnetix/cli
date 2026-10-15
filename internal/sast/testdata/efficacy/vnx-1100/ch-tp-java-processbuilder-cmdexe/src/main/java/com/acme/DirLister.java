package com.acme;

import java.io.IOException;

public class DirLister {
    public Process list(String dir) throws IOException {
~>        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "dir", dir);
        pb.redirectErrorStream(true);
        return pb.start();
    }
}
