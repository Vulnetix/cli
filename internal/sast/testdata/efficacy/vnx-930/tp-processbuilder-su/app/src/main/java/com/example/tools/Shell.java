package com.example.tools;

import java.util.Arrays;

public class Shell {
    Process start(String cmd) throws Exception {
~>        ProcessBuilder pb = new ProcessBuilder("su", "-c", cmd);
        return pb.start();
    }

    Process list(String cmd) throws Exception {
~>        return new ProcessBuilder(Arrays.asList("su", "-c", cmd))
            .redirectErrorStream(true)
            .start();
    }
}
