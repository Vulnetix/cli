package com.acme.img;

import java.io.IOException;
import java.util.List;

public class Convert {
    public int run(String input, String output) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("convert", input, output);
        pb.inheritIO();
        Process p = pb.start();
        return p.waitFor();
    }

    public void list() throws IOException {
        Runtime.getRuntime().exec(new String[] {"ls", "-l", "/tmp"});
        new ProcessBuilder(List.of("git", "status")).start();
    }
}
