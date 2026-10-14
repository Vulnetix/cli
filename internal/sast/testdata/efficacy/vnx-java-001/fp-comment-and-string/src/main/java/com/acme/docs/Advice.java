package com.acme.docs;

import java.util.logging.Logger;

/**
 * Never write Runtime.getRuntime().exec("ping " + host) in a handler.
 */
public class Advice {
    private static final Logger LOG = Logger.getLogger("advice");

    public void warn(String host) {
        // Runtime.getRuntime().exec("ping " + host);
        LOG.warning("do not call Runtime.getRuntime().exec(\"sh \" + input)");
        String example = "new ProcessBuilder(\"sh\", \"-c\", \"ls \" + dir)";
        LOG.info(example + host);
    }
}
