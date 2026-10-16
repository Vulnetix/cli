package com.acme.jobs;

import java.io.File;

public class Cleanup {
    public void purge(File spool) {
~>        for (File f : spool.listFiles()) {
            f.delete();
        }
    }
}
