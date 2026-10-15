package com.acme;

import java.io.IOException;
import java.util.List;

public class Deployer {
    public int deploy(String script) throws IOException, InterruptedException {
~>        List<String> cmd = List.of("/bin/bash", "-c", script);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.inheritIO();
        return pb.start().waitFor();
    }

    public void restart() throws IOException {
        new ProcessBuilder()
~>                .command("sh", "-c", "systemctl restart app")
                .start();
    }
}
