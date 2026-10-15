package com.acme;

import java.io.IOException;

public class Runner {
    public int run(String script) throws IOException, InterruptedException {
~>        String[] cmd = {"/bin/bash", "-c", script};
        Process p = Runtime.getRuntime().exec(cmd);
        return p.waitFor();
    }
}
