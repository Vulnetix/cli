package com.acme.boot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StartupBanner {
    private static final Logger LOG = LoggerFactory.getLogger(StartupBanner.class);

    public void print() {
        LOG.info("Starting on Java " + System.getProperty("java.version"));
        LOG.debug("OS {} {}", System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.println("tmpdir=" + System.getProperty("java.io.tmpdir"));
    }
}
