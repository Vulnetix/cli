package com.example.io;

public class Help {
    // File.createTempFile("x", ".tmp") is world-readable under the default umask
    /*
     * new File("/tmp/" + name) is predictable
     */
    static final String MSG = "avoid File.createTempFile(prefix, suffix) and new File(\"/tmp/\" + n)";
    static final String DEFAULT_DIR = "/tmp";
}
