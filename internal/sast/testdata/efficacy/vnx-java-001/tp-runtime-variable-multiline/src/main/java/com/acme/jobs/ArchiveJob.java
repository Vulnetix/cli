package com.acme.jobs;

import java.io.IOException;

public class ArchiveJob {
    private final String workDir;

    public ArchiveJob(String workDir) {
        this.workDir = workDir;
    }

    public void extract(String archive, String[] env) throws IOException {
        Runtime rt = Runtime.getRuntime();
~>        Process proc = rt.exec(
                "tar -xzf " + archive + " -C " + workDir);
        String cmd = "rm -rf ";
        cmd += archive;
~>        rt.exec(cmd, env);
    }
}
