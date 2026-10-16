package com.acme.ops;

import java.io.IOException;

public class Maint {
    private static final String BIN = "/usr/bin/rsync";
    private static final String DEST = "backup:/srv";

    public void sync() throws IOException {
        Runtime.getRuntime().exec(BIN + " -a /data " + DEST);
        Runtime.getRuntime().exec("uptime");
        // Runtime.getRuntime().exec("ping " + host);
        String doc = "never call Runtime.getRuntime().exec(\"ls \" + dir)";
        System.out.println(doc);
    }
}
