package com.acme;

import java.util.List;

public class Runner {
    public int run(String script) throws Exception {
~>        List<String> cmd = List.of("/bin/bash", "-c", script);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        return pb.start().waitFor();
    }
}
